# NetSentinel — Proof-Carrying Alerts: Full Blockchain/Integrity Implementation

> **Implements:** Both [middle.md](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/middle.md) (tamper-evident forensic integrity base layer) and [PROOF_CARRYING_ALERTS_IMPLEMENTATION_PLAN.md](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/PROOF_CARRYING_ALERTS_IMPLEMENTATION_PLAN.md) (Proof-Carrying Alert upgrade with corrections)
> **Scope:** Complete Phase 1 implementation — the core integrity pipeline with DSSE receipts, replay, release registry, witnesses, and the 9-claim verifier.

---

## User Review Required

> [!IMPORTANT]
> This is a **massive** implementation (30+ new files, 10+ modified files). The plan follows the phased approach from the docs — **Phase 1 only** (the pitch-ready sprint). Phases 2 and 3 (HSM/KMS, ZKML) are documented but deferred.

> [!WARNING]
> **New dependency:** `PyNaCl` (Ed25519 signing). It is NOT currently in `requirements.txt`. The plan adds it along with an in-repo DSSE implementation (~80 lines) to avoid the `securesystemslib` dependency and stay lightweight. `opentimestamps-client` and `rfc3161ng` are added as optional.

> [!IMPORTANT]
> **No detection behavior changes.** The six model wrappers gain a `predict_with_provenance()` sibling that calls existing `predict()` internally, captures the feature vector, and returns a `ProvenanceResult`. The `predict()` method is untouched.

---

## Open Questions

> [!IMPORTANT]
> 1. **Key storage:** For the demo, Ed25519 keys will be auto-generated and stored as files (`netsentinel/integrity/nid_ed25519.key`, `0600` perms). Is this acceptable, or do you want env-var-based key injection?
> 2. **Blob store encryption:** The plan calls for AES-GCM at rest for evidence blobs. For the demo, should we use a simple static key (from config), or skip encryption and just use plaintext blob storage?
> 3. **External anchoring:** middle.md recommends OpenTimestamps (Bitcoin anchoring). For initial implementation, should we start with the **Git commit fallback** (simplest, works offline) and add OTS later, or go straight to OTS?
> 4. **Frontend scope:** The plan adds a 9-claim verification panel, integrity dashboard view, and action timeline to the React frontend. Should we implement the full frontend, or start backend-only and add frontend later?

---

## Proposed Changes

### Component 1: Encoding & Canonicalization Foundation

> Replaces `middle.md` §B.3's `json.dumps(sort_keys=True)` with RFC 8785 (JCS) over a restricted value domain (no floats in signed payloads).

#### [NEW] [`encoding.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/encoding.py)
- `jcs_canonicalize(obj) → bytes` — RFC 8785 over restricted domain (no floats)
- `assert_canonicalizable(obj) → None` — raises `CanonicalizationError` on float
- `digest_prefixed(b: bytes) → str` — `"sha256:" + hexdigest`
- Value domain: objects with string keys (sorted), arrays, str, int, bool, None. **NO float.**
- Timestamps → RFC 3339 UTC strings + `unix_seconds: int`
- Scores → `score_ppm: int` (0–1,000,000)

#### [NEW] [`__init__.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/__init__.py)
- Package init for `netsentinel.integrity`

---

### Component 2: Merkle Tree (from middle.md §B.2 — kept unchanged)

#### [NEW] [`merkle.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/merkle.py)
- Domain-separated leaf/node hashing (0x00/0x01 prefix)
- `build_tree(leaves) → (root, proofs)` — treats inputs as raw content, applies `leaf_hash` internally
- `verify_proof(leaf, proof, root) → bool`
- `consistency_proof(leaves, old_size, new_size)` — RFC 6962 §2.1.2 algorithm
- `verify_consistency(old_root, old_size, new_root, new_size, proof) → bool`
- Handles odd leaf counts (duplicate last) and single-leaf case

---

### Component 3: DSSE Envelope & Receipt (replaces middle.md §B.8)

#### [NEW] [`envelope.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/envelope.py)
- In-repo DSSE implementation (~80 lines, Ed25519 via PyNaCl)
- `sign_receipt(statement: dict, sk: SigningKey) → dict` — PAE construction + Ed25519 sign
- `verify_envelope(env: dict, vk: VerifyKey) → dict` — recompute PAE, verify, return parsed statement
- `PAYLOAD_TYPE = "application/vnd.in-toto+json"`

#### [NEW] [`receipt.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/receipt.py)
- `ReceiptBuilder` — constructs in-toto Statement v1 with NetSentinel predicate
- Predicate type: `https://netsentinel.dev/attestation/ml-alert/v1`
- Fields: sensor info, evidence digest, feature pipeline digests, model identity, decision (class, `score_ppm`, threshold, policy digest), completeness chain (`previous_receipt_digest`, `event_sequence`, `checkpoint_root`)
- Two forms: pre-anchor (no checkpoint_root) and anchored (with inclusion proof + checkpoint ref)

---

### Component 4: Append-Only Ledger (extends middle.md §B.4)

#### [NEW] [`ledger.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/ledger.py)
- `Block` dataclass — RFC 3339 timestamps (not floats), `checkpoint_sequence`
- `SignedTreeHead` — tree_size, root_hash, timestamp (RFC 3339 + unix_seconds int)
- `IntegrityLedger` — append, verify_chain, build_sth, consistency_proof
- Ed25519 signing via PyNaCl
- Append-only JSONL storage
- Empty-window commitments (every window produces a block, even with 0 alerts)

---

### Component 5: Anchor Service (extends middle.md §B.5)

#### [NEW] [`anchor_service.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/anchor_service.py)
- `AnchorService` — batches DSSE envelope digests (not raw alerts) into Merkle windows
- `add_envelope(alert_id, envelope)` — leaf = digest of envelope bytes
- `flush()` — builds Merkle tree, appends block to ledger, stores per-alert proofs
  - **Emits blocks for empty windows** (completeness)
- `publish_sth()` — daily STH + external anchor submission

#### [NEW] [`proof_store.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/proof_store.py)
- Stores per-alert: envelope, Merkle proof, block index, checkpoint reference
- JSON file-backed for the demo

---

### Component 6: Provenance Wiring (changes to existing model files)

#### [MODIFY] [`registry.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/registry.py)
- Add `model_identity(name) → ModelIdentity(digest_prefixed, version, path, loaded_ok)`
- Compute `sha256(file_bytes)` for each ONNX file at load time
- New `_model_digests: dict[str, str]` populated during `load_all()`

#### [MODIFY] [`ddos.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/ddos.py)
- Add `predict_with_provenance(features) → ProvenanceResult` sibling
- Returns: prediction class, score_ppm, feature_names, feature_values, preprocessor_ref
- Existing `predict()` is **completely untouched**

#### [MODIFY] [`c2_beacon.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/c2_beacon.py), [`dga.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/dga.py), [`encrypted.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/encrypted.py), [`exfiltration.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/exfiltration.py), [`port_scan.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/port_scan.py)
- Same pattern: add `predict_with_provenance()` sibling on each wrapper
- No behavioral changes to existing prediction logic

#### [NEW] [`codehash.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/codehash.py)
- Deterministically hash the code that could change predictions
- Fixed manifest: extractor/*.py, models/*.py wrappers, integrity/encoding.py
- JCS digest of `{file: sha256}` + git commit state

---

### Component 7: Receipt Sealing & Completeness

#### [NEW] [`sealing.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/sealing.py)
- `ReceiptSealer` — per-sensor monotonic counter + `previous_receipt_digest` chain
- SQLite table `receipt_seq` for crash-safe counter persistence
- Gap/sequence detection

#### [NEW] [`completeness.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/completeness.py)
- Monitor thread: checks each new block against persisted head
- Fork, roll-back, stall detection → `COMPLETENESS_ALERT`
- Cadence verification (wall-clock vs configured `window_seconds`)

---

### Component 8: Blob Store & Replay Engine

#### [NEW] [`blobstore.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/blobstore.py)
- Stores feature vectors, evidence blobs per alert (encrypted at rest, off-chain)
- File-backed for demo
- Retention policy: `blob_retention_days` with digest-preserving deletion

#### [NEW] [`replay.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/replay.py)
- Deterministic inference replay per model class
- `onnxruntime.SessionOptions`: `intra_op_num_threads=1`, `inter_op_num_threads=1`
- Compares `score_ppm` equality + class equality
- Returns `PASS | FAIL | UNVERIFIABLE(reason)`

---

### Component 9: Signed Model Release Registry

#### [NEW] [`releases.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/releases.py)
- Append-only `releases.jsonl` — one record per model version
- `ReleaseChecker.check(identity) → verdict` — refuses/flags unsigned, revoked, stale, schema-mismatched models
- Tier-A signing: Ed25519 release key (separate from sensor key)

#### [NEW] [`releases.jsonl`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/models/releases.jsonl)
- Initial release records for all 6 models (auto-generated from loaded digests)

---

### Component 10: Selective Disclosure

#### [NEW] [`disclosure.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/disclosure.py)
- Per-alert salted field commitments → Merkle root (`evidence.commitment_root`)
- `disclose(alert_id, fields) → {field, value, salt, merkle_path, commitment_root}`
- No PII/IPs in receipts or on-chain

---

### Component 11: Analyst-Decision Provenance

#### [NEW] [`actions.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/actions.py)
- Action types: acknowledged, classification_changed, evidence_accessed, escalated, closed, disclosed
- Per-alert action chain with `previous_action_digest`
- Actions feed into anchor service as a second leaf class

---

### Component 12: Nine-Claim Verifier

#### [NEW] [`claims.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/claims.py)
- Every claim returns `PASS | FAIL | UNVERIFIABLE(reason)` — **three states, never bare boolean**
- Claims:
  1. Evidence intact (re-JCS evidence → digest match)
  2. Features intact (re-JCS feature vector → digest match)
  3. Approved model (digest in release log, not revoked)
  4. Approved pipeline (extractor/preprocessor digests match)
  5. Prediction reproducible (replay engine)
  6. Policy intact (policy_digest recomputable)
  7. Alert included (Merkle inclusion proof)
  8. History consistent (consistency proof vs witness-cached checkpoint)
  9. Externally timestamped (OTS/RFC 3161/witness quorum)

---

### Component 13: Witness Server

#### [NEW] [`witnesses.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/witnesses.py)
- Witness protocol: verify sensor sig, check consistency, countersign checkpoint
- Fork detection and evidence preservation

#### [NEW] [`witness_server.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/scripts/witness_server.py)
- Standalone FastAPI witness (~150 lines)
- `POST /witness/v1/cosign`

---

### Component 14: Anchoring Backends

#### [NEW] [`anchors/__init__.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/anchors/__init__.py)
#### [NEW] [`anchors/base.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/anchors/base.py)
- `AnchorBackend.submit(checkpoint_digest) → AnchorAttestation`

#### [NEW] [`anchors/git.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/anchors/git.py)
- Git commit STH to repo — demo fallback, labeled low-strength

#### [NEW] [`anchors/ots.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/anchors/ots.py)
- OpenTimestamps client wrapper — default public-chain anchor

#### [NEW] [`anchors/rfc3161.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/integrity/anchors/rfc3161.py)
- RFC 3161 TSA client — enterprise anchor

---

### Component 15: Pipeline Integration (wiring it all together)

#### [MODIFY] [`analyzer.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/pipeline/analyzer.py)
- After alert creation, capture provenance and issue receipt:
  ```python
  prov = registry.predict_with_provenance_result_for(alert)
  receipt = receipt_builder.build(alert, prov, sensor_ctx)
  envelope = envelope.sign_receipt(receipt, signing_key)
  anchor_service.add_envelope(alert["alert_id"], envelope)
  blob_store.put(alert_id, feature_blob, evidence_blob)
  ```
- **No changes to prediction logic** — additive hook only

#### [MODIFY] [`alert_manager.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/pipeline/alert_manager.py)
- Add `receipt_ref` field on stored alerts (envelope digest)

#### [MODIFY] [`main.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/main.py)
- Startup sequence: key load/gen → model digests → release check → integrity services init → completeness monitor → flush/STH timers
- Add background tasks: `flush()` every `window_seconds`, `publish_sth()` every `checkpoint_interval`

---

### Component 16: API Surface

#### [MODIFY] [`routes.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/api/routes.py)
New endpoints:
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/integrity/receipt/{alert_id}` | Portable Proof-Carrying Alert package |
| GET | `/api/integrity/verify/{alert_id}` | Nine-claim verification report |
| POST | `/api/integrity/replay/{alert_id}` | Deterministic inference replay |
| GET | `/api/integrity/checkpoints` | Checkpoint timeline |
| GET | `/api/integrity/consistency` | Consistency proof vs published STH |
| POST | `/api/integrity/disclose/{alert_id}` | Selective field disclosure |
| GET | `/api/models/status` | Release-policy verdicts per model |
| GET | `/api/models/releases` | Release transparency log |
| POST | `/api/alerts/{alert_id}/actions` | Analyst-decision provenance |
| GET | `/api/alerts/{alert_id}/actions` | Action chain for an alert |
| POST | `/witness/v1/cosign` | Witness cosign endpoint |

#### [MODIFY] [`websocket.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/api/websocket.py)
New WS event types:
- `receipt_issued`, `checkpoint_anchored`, `integrity_claim_update`
- `completeness_alert`, `witness_fork`, `model_policy_violation`

---

### Component 17: Config & Dependencies

#### [MODIFY] [`config.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/netsentinel/config.py)
Add integrity configuration block:
```python
# Integrity / Proof-Carrying Alerts
INTEGRITY_ENABLED = True
SENSOR_ID = "sensor-07"
INTEGRITY_WINDOW_SECONDS = 60
INTEGRITY_CHECKPOINT_INTERVAL = 86400
INTEGRITY_LEDGER_PATH = "netsentinel/integrity/ledger.jsonl"
INTEGRITY_KEY_PATH = "netsentinel/integrity/nid_ed25519.key"
INTEGRITY_BLOB_STORE_PATH = "netsentinel/integrity/blobs"
INTEGRITY_BLOB_RETENTION_DAYS = 30
INTEGRITY_ANCHORS = ["git"]  # Start with git, add "opentimestamps", "rfc3161"
INTEGRITY_WITNESS_QUORUM = {"threshold": 2, "witnesses": ["witness-a", "rfc3161"]}
MODEL_RELEASE_POLICY = "FLAG"  # FLAG | REFUSE
```

#### [MODIFY] [`requirements.txt`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/requirements.txt)
Add:
```
PyNaCl>=1.5.0              # Ed25519 signing
# Optional:
# opentimestamps-client    # Bitcoin anchoring
# rfc3161ng                # RFC 3161 timestamping
```

---

### Component 18: Standalone CLI Verifier

#### [NEW] [`netsentinel_verify.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/tools/netsentinel_verify.py)
- `python tools/netsentinel_verify.py receipt-package.json [--replay] [--anchors-file]`
- Offline verification: DSSE sig check, digest rebuilds, inclusion + consistency proofs
- With `--replay`: re-run inference from embedded feature blob
- Exit codes per claim class for scripting

---

### Component 19: Documentation

#### [NEW] [`INTEGRITY.md`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/docs/INTEGRITY.md)
- Term definitions (transparency log vs blockchain)
- Anchor-strength table
- Architecture overview

#### [NEW] [`EVIDENTIARY_STANDARDS.md`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/docs/EVIDENTIARY_STANDARDS.md)
- FRE 901/902, eIDAS, NIST SP 800-201 mapping
- Corrected legal wording (Correction 6 — "may support", never "guarantees")

---

### Component 20: Tests

#### [NEW] [`test_encoding.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/tests/test_encoding.py)
- RFC 8785 Appendix B vectors, float rejection, cross-check

#### [NEW] [`test_integrity.py`](file:///c:/Users/gtrip/OneDrive/Desktop/wearecharliekirk-main/wearecharliekirk-main/tests/test_integrity.py)
- Tests 1–7 from middle.md §B.11 (Merkle, ledger, tamper, batching, consistency)
- Tests 8–18 from the proof-carrying plan (receipt, replay, releases, completeness, witnesses, disclosure, actions)

---

## Implementation Order

Following Part 19 from the proof-carrying plan — **Phase 1 only**:

| Step | Component | Tests |
|------|-----------|-------|
| 1 | `encoding.py` — RFC 8785 JCS canonicalization | test_encoding.py (RFC 8785 vectors, float rejection) |
| 2 | `merkle.py` — domain-separated Merkle tree + consistency proofs | test_integrity: Merkle correctness (N=1, even, odd) |
| 3 | `envelope.py` + `receipt.py` — DSSE + in-toto receipts | test_integrity: receipt round-trip, wrong-key fail |
| 4 | `ledger.py` — append-only Ed25519 signed blocks, STH, consistency | test_integrity: ledger linkage, tamper detection |
| 5 | Model provenance wiring — `predict_with_provenance()` on all 6 wrappers, registry digests, `codehash.py` | test_integrity: provenance capture |
| 6 | `anchor_service.py` + `proof_store.py` — DSSE leaves, empty-window commitments | test_integrity: batching/scale (10k alerts → 1 block) |
| 7 | `sealing.py` + `completeness.py` — monotonic counter, gap detection | test_integrity: completeness |
| 8 | `blobstore.py` + `replay.py` — deterministic replay engine | test_integrity: replay PASS fixtures, tamper detection |
| 9 | `releases.py` — model release registry + enforcement | test_integrity: release policy verdicts |
| 10 | `claims.py` — 9-claim verifier | test_integrity: full claim verification |
| 11 | `witnesses.py` + `witness_server.py` — witness protocol | test_integrity: witness quorum, fork detection |
| 12 | `anchors/*` — Git backend (OTS/RFC 3161 optional) | test_integrity: anchor fallbacks |
| 13 | `disclosure.py` + `actions.py` — selective disclosure + analyst actions | test_integrity: disclosure, action chain |
| 14 | Pipeline wiring — `analyzer.py`, `alert_manager.py`, `main.py` integration | End-to-end test |
| 15 | API endpoints — all `/api/integrity/*` routes + WS events | API test |
| 16 | CLI verifier — `tools/netsentinel_verify.py` | CLI test |
| 17 | Config + dependencies | — |
| 18 | Documentation — `INTEGRITY.md`, `EVIDENTIARY_STANDARDS.md` | — |

---

## Verification Plan

### Automated Tests
```bash
# Run full integrity test suite
python -m pytest tests/test_encoding.py tests/test_integrity.py -v

# Verify existing tests still pass (no regression)
python -m pytest tests/ -v --ignore=tests/test_encoding.py --ignore=tests/test_integrity.py
```

### Manual Verification
1. **Tamper demo:** Start server, generate alerts, manually edit an alert in memory, call `/api/integrity/verify/{id}` → should show `FAIL` on claims 1, 2, 7
2. **Replay demo:** Call `/api/integrity/replay/{id}` → should show `PASS` (class + score match)
3. **Key compromise demo:** Rewrite ledger blocks, verify consistency against published STH → should fail even though local chain-walk passes
4. **Empty-window test:** Stop simulator, wait >60s, verify blocks still produced (alert_count=0)

---

## File Map Summary

| Category | Count | Files |
|----------|-------|-------|
| **New (integrity/)** | 18 | encoding.py, merkle.py, envelope.py, receipt.py, ledger.py, anchor_service.py, proof_store.py, sealing.py, completeness.py, blobstore.py, replay.py, releases.py, disclosure.py, actions.py, claims.py, codehash.py, witnesses.py, anchors/{base,git,ots,rfc3161}.py |
| **New (other)** | 5 | scripts/witness_server.py, tools/netsentinel_verify.py, tests/test_encoding.py, tests/test_integrity.py, docs/INTEGRITY.md, docs/EVIDENTIARY_STANDARDS.md |
| **Modified** | 10 | registry.py, ddos.py, c2_beacon.py, dga.py, encrypted.py, exfiltration.py, port_scan.py, analyzer.py, alert_manager.py, main.py, routes.py, websocket.py, config.py, requirements.txt |
