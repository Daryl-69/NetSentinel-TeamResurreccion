# NetSentinel — Tamper-Evident Forensic Integrity (Blockchain) : Research + Implementation Plan

> **For:** an AI coding agent with direct access to the NetSentinel Python repo
> (`C:\Users\gtrip\OneDrive\Desktop\netsentinel\`), plus context for the team.
> **Scope:** Add a **tamper-evident chain-of-custody layer** for alerts and forensic
> evidence. This is the ONLY defensible use of blockchain in a NIDS. Do NOT use blockchain
> for detection, and do NOT store raw traffic on-chain.
> **Additive only** — does not modify any detection model or the extraction pipeline.
>
> **v2 update:** adds Certificate-Transparency-style consistency proofs, addresses the
> "compromised signing key" threat model, standardizes the proof format (Chainpoint-like),
> and adds an evidentiary/legal-admissibility mapping section.

---

## PART A — RESEARCH & JUSTIFICATION (why this design, not the hype version)

### A.1 The honest problem statement

NetSentinel produces forensic artifacts: *"host X scanned host Y at 19:56, here is the
evidence."* In a SOC or a legal context, the first question is: **"how do we know this
alert was not fabricated, deleted, or edited after the fact?"**

A plain database can be silently modified by anyone with DB access — including:
- an attacker who compromises the NIDS host and **deletes the alert that incriminates
  them** (MITRE ATT&CK **T1070 – Indicator Removal on Host**, a documented real technique),
- a malicious insider covering their tracks.

We cannot *prevent* deletion on a single host. The achievable, valuable goal is to make any
tampering **cryptographically detectable and provable** — a tamper-evident chain of custody.

### A.2 What NOT to build (and why — state this to judges)

| Anti-pattern | Why it's wrong |
|---|---|
| "Detect attacks using blockchain" | Detection is ML/heuristics; blockchain adds nothing. Pure buzzword. |
| "Store all packets/flows on-chain" | Infeasible. Hyperledger Fabric caps ~**70 TPS** for write-heavy logging (AUDITEM, arXiv:2207.00370); on-chain storage grows linearly and becomes a liability (MDPI 2025). |
| "Consensus-based detection across nodes" | Massive scope, no benefit for a single-sensor project. |

Saying *"we deliberately did not do these"* demonstrates real understanding. This is not a
strawman: the current literature is genuinely full of this scope-creep. Surveys of
blockchain-in-IDS work catalog many systems that use Hyperledger Fabric, Ethereum, or custom
chains specifically for **detection or federated-model consensus** rather than evidentiary
integrity — and explicitly flag the cost of doing so: implementing blockchain in IDSs poses
challenges, requiring significant technical expertise and potentially introducing new
vulnerabilities including 51% attacks, smart contract exploits, and consensus-related
threats. Citing this contrast — "the field is full of misuse; we deliberately scoped to the
one defensible use" — is stronger than simply asserting the anti-pattern table.

### A.3 Industry precedent (the pattern everyone actually uses: **anchoring**)

Nobody puts real data on-chain. They hash data off-chain and put only the **hash** on an
immutable, append-only ledger.

- **Guardtime KSI (Keyless Signature Infrastructure)** — most prominent commercial
  solution, deployed nationally in **Estonia** for government/health records. Value:
  independent verifiability — even the data host "would not be able to present partial or
  selected data, or manipulate any audit trails." Marketed as **"truth over trust."**
  KSI scales by batching all signatures per second into a **Merkle tree** and anchoring a
  single root. *(e-Estonia; Guardtime TrueTrail.)*
- **BlockAudit / BlockTrail (Hyperledger)** — academic frameworks converting conventional
  enterprise audit logs into tamper-proof logs with "higher security, integrity, and fault
  tolerance." *(BlockTrail, ResearchGate 334483237.)*
- **LogStamping (2025)** — current best practice: **hybrid on-chain/off-chain.** Full logs
  → IPFS/distributed storage; only the **hash is recorded on the blockchain**, "creating a
  lightweight and verifiable audit trail." *(arXiv:2505.17236.)*
- **Certificate Transparency (CT)** — the largest production deployment of exactly this
  batching-plus-Merkle-tree pattern, run at internet scale by browser vendors. The
  append-only property of each log is achieved using Merkle Trees, which can show that any
  particular version of the log is a superset of any previous version, avoiding blind trust
  in the log operator — if a log tries to show different things to different people, this
  is efficiently detectable by comparing tree roots and consistency proofs. Practically,
  this scales extremely well: foundational work by Crosby and Wallach showed a log of 80
  million events requires only 3 KB of proof to verify append-only-ness.
- **B-CoC** — an Ethereum-based academic prototype directly analogous to this project's
  goal: a Blockchain-based Chain of Custody system designed to dematerialize the CoC
  process, guaranteeing auditable integrity of collected evidence and traceability of
  owners.
- **OpenTimestamps** — a free, purpose-built protocol for exactly the "anchor a batched
  Merkle root to a public chain" pattern: it standardizes how timestamps are created and
  verified against public blockchains, and a proof file contains the Merkle path connecting
  a document's hash to a specific Bitcoin block header, verifiable with no trusted third
  party. Its calendar servers already implement your batching model: they collect hashes
  from thousands of users over a defined interval and aggregate them into a single Merkle
  tree, producing one Merkle root per window.

**Common benefit:** integrity + non-repudiation + independent auditability **without
trusting the party that holds the logs.**

### A.4 Scalability truth (design constraint, not an afterthought)

- Hyperledger Fabric write throughput ≈ **70 TPS** (AUDITEM, arXiv:2207.00370) — far below
  NIDS alert bursts. ⇒ **never anchor one transaction per alert.**
- On-chain storage grows **linearly** ⇒ keep full data off-chain (MDPI 2025).
- Hash-only designs risk unrecoverable data if raw logs are lost before archiving
  (LogStamping) ⇒ keep full alerts in the existing DB; the ledger is for *verification*, not
  primary storage.

**Resolution → Merkle batching + periodic anchoring.** Hash many alerts into one Merkle
tree; anchor ONE root per time window. One anchor protects thousands of alerts ⇒ throughput
is decoupled from alert volume (≈1 anchor/minute). This is exactly the KSI model, and the
same model Certificate Transparency and OpenTimestamps use at internet scale.

### A.5 The threat model gap: what a linear hash-chain does NOT protect against

A linear hash-chain (each block references `prev_block_hash`, signed with a local Ed25519
key) is tamper-evident against **partial compromise** — someone editing the alert DB
without touching the ledger, or editing an old ledger entry without re-signing everything
downstream. It is **not** sufficient against **full host compromise**, where the attacker
also obtains the private signing key: they can then rewrite the entire ledger file and
re-sign every block, and a naive `verify_chain()` walk would report green.

This is the same problem Certificate Transparency solves with **Signed Tree Heads (STH) +
consistency proofs**, and it is why CT does not rely solely on a log operator's local
signature:
- CT logs achieve tamper-evidence by periodically signing the *whole-tree state*: a log
  combines new certificates into a new Merkle tree hash with the old tree hash, and the
  resulting new Merkle tree hash is signed to create a new Signed Tree Head.
- Because relying parties don't want to blindly trust one operator's signature, CT is
  audited externally rather than self-asserted: independent **monitors and auditors**
  (and, in gossip-based designs, relying parties exchanging observed STHs) continuously
  check consistency proofs between successive Signed Tree Heads. If a log ever tries to
  show different histories to different parties (a "split view") or silently rewrites past
  entries, the mismatching STHs make it detectable — no single operator's signature is
  trusted on its own.

**Design implication for NetSentinel:** treat *publishing the ledger's Signed Tree Head
somewhere outside the NIDS host* as a **core** requirement, not an optional stretch goal —
it is the only mitigation for the "attacker also steals the signing key" scenario. See §B.7
(updated) and §B.12.

### A.6 Evidentiary / legal-admissibility alignment

This design is not just an engineering nicety — it maps onto how courts and regulators
actually evaluate electronic evidence, which strengthens the "why blockchain, specifically"
argument beyond a hackathon audience.

- **US Federal Rules of Evidence:** blockchain-anchored evidence does not get a special
  legal category — it is evaluated under the same authentication rules as any electronic
  record. Under FRE 901, the proponent must show data was collected through a documented,
  reproducible process with integrity preserved through cryptographic verification from the
  moment of acquisition. FRE 902(13)–(14) go further, permitting **self-authentication** of
  electronic evidence generated by a reliable process — blockchain-anchored records can
  meet this through certified hashes and timestamping.
- **EU eIDAS Regulation (910/2014):** electronic timestamps cannot be denied legal
  admissibility solely because they are electronic, and *qualified* electronic timestamps
  carry a legal presumption of accuracy across all 27 EU member states.
- **NIST:** NIST's forensic-readiness guidance frames the need to proactively preserve
  evidence integrity so it can be collected and relied upon in a later investigation
  (**NIST SP 800-201**, *Cloud Computing Forensic Reference Architecture*, 2024), and its
  log-management guidance specifically calls for protecting log integrity and detecting
  unauthorized modification (**NIST SP 800-92**). Tamper-evident, hash-anchored alert logs
  are a direct realization of both.
- **Judicial precedent that hash-anchoring specifically has been accepted:** China's
  Hangzhou Internet Court ruled in 2018 that blockchain-stored evidence was admissible,
  provided the underlying technology's reliability was demonstrated — the court examined
  the technical process used to capture/store the evidence and the integrity of the hash
  chain.
- **What courts look for, restated as three conditions:** authenticity, integrity confirmed
  via cryptographic hash, and a documented chain of custody accounting for every access and
  transfer — which maps directly onto this design's canonical-JSON hashing, Merkle proofs,
  and signed append-only ledger.

### A.7 Sources
- Guardtime KSI / Estonia — https://e-estonia.com/ksi-blockchain-provides-truth-over-trust/
- LogStamping (hybrid on/off-chain + IPFS), arXiv:2505.17236 — https://arxiv.org/pdf/2505.17236
- BlockTrail (scalable multichain audit trails), ResearchGate 334483237
- AUDITEM (~70 TPS Hyperledger benchmark), arXiv:2207.00370 — https://arxiv.org/pdf/2207.00370
- Decentralized tamper-proof logging, MDPI Future Internet 2025, 17(3):108 — https://www.mdpi.com/1999-5903/17/3/108
- Framework for Blockchain-Based Access Logs & Tamper-Proof Audit Trails, ResearchGate 392312120
- Certificate Transparency — RFC 6962 background & explainer docs (certificate.transparency.dev, Wikipedia "Certificate Transparency")
- Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging" (2009)
- B-CoC: Blockchain-based Chain of Custody (academic prototype, Ethereum)
- OpenTimestamps protocol docs — https://opentimestamps.org
- NIST SP 800-201, *Cloud Computing Forensic Reference Architecture* (2024, forensic readiness) — https://csrc.nist.gov/pubs/sp/800/201/final
- NIST SP 800-92, *Guide to Computer Security Log Management* (log integrity)
- FRE 901, FRE 902(13)–(14); EU eIDAS Regulation (EU) 910/2014
- Hangzhou Internet Court blockchain-evidence ruling (2018) — reporting on the case

---

## PART B — IMPLEMENTATION PLAN

### B.1 Architecture (hash-anchor pattern)

alert generated ──► canonical JSON ──► SHA-256 ──► leaf hash │ collect leaves over a window (default 60s) ──► build Merkle tree ──► root hash │ append a signed block to an append-only hash-chained ledger: block = { index, timestamp, merkle_root, prev_block_hash, alert_count, nid_pubkey, signature(Ed25519) } block_hash = SHA-256(index || timestamp || merkle_root || prev_block_hash || alert_count) │ periodically (e.g. daily), build a TOP-LEVEL Merkle tree over all block_hashes, sign a Signed Tree Head (STH), and publish the STH externally (§B.7) so no single host — even if fully compromised — can rewrite history undetected.


Full alerts stay in the existing DB (off-chain). The ledger stores only 32-byte roots +
metadata. Tampering with any past alert changes its leaf → changes the Merkle root → the
stored block no longer matches → and every subsequent block's `prev_block_hash` breaks.
Tampering with an *old block itself* (requiring the attacker to also have the signing key)
is caught by the consistency proof against a previously published, externally-anchored STH.
This is a genuine (single-writer, permissioned) blockchain, hardened with the same
append-only auditing pattern used by Certificate Transparency.

### B.2 New file: `netsentinel/integrity/merkle.py`

```python
import hashlib
from typing import NamedTuple

def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def leaf_hash(canonical_bytes: bytes) -> bytes:
    return _h(b"\x00" + canonical_bytes)      # 0x00 domain-sep for leaves

def _node(a: bytes, b: bytes) -> bytes:
    return _h(b"\x01" + a + b)                 # 0x01 domain-sep for internal nodes

class MerkleProof(NamedTuple):
    leaf_index: int
    siblings: list[tuple[bytes, str]]          # (hash, "L"|"R")

def build_tree(leaves: list[bytes]) -> tuple[bytes, list[MerkleProof]]:
    """Return (root, per-leaf proofs). Duplicate last node if odd count."""
    # standard bottom-up Merkle construction; record sibling path for each leaf.
    ...

def verify_proof(leaf: bytes, proof: MerkleProof, root: bytes) -> bool:
    h = leaf
    for sib, side in proof.siblings:
        h = _node(sib, h) if side == "L" else _node(h, sib)
    return h == root
```

Requirements:

Deterministic. Include domain-separation bytes (leaf vs node) to prevent second-preimage attacks.
Handle odd leaf counts (duplicate last) and the single-leaf case (root == leaf_hash).
Unit-tested against known vectors.

**Leaf-input contract (fix one inconsistency in v2):** decide ONE rule for what
`build_tree` receives and apply it everywhere. `anchor_service.flush()` passes
already-`leaf_hash`-ed alert bytes, but `ledger.build_sth()` passes raw `block_hash`
bytes — so the two trees domain-separate their leaves differently. Recommended: make
`build_tree` treat its inputs as **raw content** and apply `leaf_hash` internally, then
have `anchor_service` pass canonical bytes (not pre-hashed) and `build_sth` pass raw
block-hash bytes. Whatever you choose, the same rule MUST hold at build-time and
verify-time or proofs silently fail.

### B.3 New file: `netsentinel/integrity/canonical.py`

```python
import json

ALERT_INTEGRITY_FIELDS = [
    "alert_id", "timestamp", "threat_type", "src_ip", "dst_ip",
    "confidence", "mitre", "evidence",
]

def canonical_alert_bytes(alert: dict) -> bytes:
    """Stable, sorted-key JSON of the fields that must not change.
    MUST be identical at write-time and verify-time."""
    subset = {k: alert[k] for k in ALERT_INTEGRITY_FIELDS if k in alert}
    return json.dumps(subset, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")
```

Rule: canonicalization must be byte-stable (sorted keys, fixed separators, no floats that re-serialize differently — store confidence as a fixed-precision string if needed).

### B.4 New file: `netsentinel/integrity/ledger.py`
```python
import time, hashlib, json
from dataclasses import dataclass, asdict
from nacl.signing import SigningKey, VerifyKey   # PyNaCl (Ed25519)

GENESIS_PREV = b"\x00" * 32

@dataclass
class Block:
    index: int
    timestamp: float
    merkle_root: str          # hex
    prev_block_hash: str      # hex
    alert_count: int
    nid_pubkey: str           # hex
    signature: str            # hex (Ed25519 over block_hash)

    def block_hash(self) -> str:
        payload = f"{self.index}|{self.timestamp}|{self.merkle_root}|" \
                  f"{self.prev_block_hash}|{self.alert_count}".encode()
        return hashlib.sha256(payload).hexdigest()

@dataclass
class SignedTreeHead:
    tree_size: int             # number of blocks covered
    root_hash: str             # hex, top-level Merkle root over block_hash()es
    timestamp: float
    nid_pubkey: str
    signature: str             # hex (Ed25519 over tree_size||root_hash||timestamp)

class IntegrityLedger:
    def __init__(self, db_path, signing_key: SigningKey):
        self.db_path = db_path            # append-only file OR sqlite table
        self.sk = signing_key
        self.vk_hex = signing_key.verify_key.encode().hex()
        self._head = self._load_head()    # last Block or None

    def append(self, merkle_root_hex: str, alert_count: int) -> Block:
        prev = self._head.block_hash() if self._head else GENESIS_PREV.hex()
        idx = (self._head.index + 1) if self._head else 0
        blk = Block(idx, time.time(), merkle_root_hex, prev, alert_count,
                    self.vk_hex, "")
        blk.signature = self.sk.sign(bytes.fromhex(blk.block_hash())).signature.hex()
        self._persist(blk); self._head = blk
        return blk

    def verify_chain(self) -> tuple[bool, int | None]:
        """Re-walk the whole ledger. Return (ok, first_bad_index)."""
        prev = GENESIS_PREV.hex()
        for blk in self._iter_blocks():
            if blk.prev_block_hash != prev: return False, blk.index
            vk = VerifyKey(bytes.fromhex(blk.nid_pubkey))
            try: vk.verify(bytes.fromhex(blk.block_hash()),
                           bytes.fromhex(blk.signature))
            except Exception: return False, blk.index
            prev = blk.block_hash()
        return True, None

    def build_sth(self) -> SignedTreeHead:
        """Build a top-level Merkle tree over all block_hash()es and sign it.
        This is the artifact that gets published externally (see anchor_service)."""
        blocks = list(self._iter_blocks())
        leaves = [bytes.fromhex(b.block_hash()) for b in blocks]
        root, _ = build_tree(leaves) if leaves else (GENESIS_PREV, [])
        sth = SignedTreeHead(len(blocks), root.hex(), time.time(), self.vk_hex, "")
        payload = f"{sth.tree_size}|{sth.root_hash}|{sth.timestamp}".encode()
        sth.signature = self.sk.sign(payload).signature.hex()
        return sth

    def consistency_proof(self, old_size: int, new_size: int) -> list[str]:
        """Prove the tree at new_size is old tree + appended blocks only.
        Standard CT-style consistency proof (RFC 6962 §2.1.2 algorithm)."""
        blocks = list(self._iter_blocks())[:new_size]
        leaves = [bytes.fromhex(b.block_hash()) for b in blocks]
        return _consistency_proof(leaves, old_size, new_size)  # helper in merkle.py

def verify_consistency(old_root: str, old_size: int,
                        new_root: str, new_size: int,
                        proof: list[str]) -> bool:
    """Relying-party-side check: does new_root really extend old_root?
    Does NOT require re-hashing the whole ledger — this is the point."""
    ...
```

Notes:

- Key management: generate an Ed25519 keypair once at first run; store the private key securely (env var / OS keystore / file with 0600 perms — document the tradeoff). Publish the public key so anyone can verify. For the demo, a local key file is fine — note in docs that production would use an HSM/KMS.
- Ledger storage: an append-only JSONL file is enough for the demo; sqlite table also fine.
- consistency_proof / verify_consistency are new in v2 — they are what let an external auditor who cached last week's STH prove today's ledger strictly extends it, in O(log n), without re-verifying every block. This closes the gap in §A.5.
### B.5 New file: `netsentinel/integrity/anchor_service.py`
Batches alerts into windows and drives the ledger.

```python
class AnchorService:
    def __init__(self, ledger, window_seconds=60, store=None):
        self.ledger = ledger
        self.window = window_seconds
        self.store = store               # maps alert_id -> {root, proof, block_index}
        self._buffer = []                # (alert_id, leaf_bytes)

    def add_alert(self, alert: dict):
        leaf = leaf_hash(canonical_alert_bytes(alert))
        self._buffer.append((alert["alert_id"], leaf))

    def flush(self):                     # call every `window` seconds / on batch end
        if not self._buffer: return None
        ids   = [a for a, _ in self._buffer]
        leaves= [l for _, l in self._buffer]
        root, proofs = build_tree(leaves)
        block = self.ledger.append(root.hex(), len(leaves))
        for aid, proof in zip(ids, proofs):
            self.store.save_proof(aid, root.hex(), proof, block.index)  # off-chain
        self._buffer.clear()
        return block

    def publish_sth(self):
        """Daily job: build STH, publish externally, persist for consistency checks."""
        sth = self.ledger.build_sth()
        self._publish_external(sth)      # e.g. Gist commit or OpenTimestamps stamp
        self.store.save_sth(sth)
        return sth
```

Integration point: wherever alerts are emitted to the WebSocket/DB, also call `anchor_service.add_alert(alert)`. A background timer (or the batch-end hook in `analyzer.py`) calls `flush()` every `window_seconds`. A second, daily timer calls `publish_sth()`. Never anchor per alert.

### B.6 Verification API (backend) + dashboard "Verify" button
Backend endpoint (FastAPI), reuse existing app:

```python
@app.get("/api/integrity/verify/{alert_id}")
def verify_alert(alert_id: str):
    alert = db.get_alert(alert_id)                       # current stored alert
    rec   = proof_store.get(alert_id)                    # {root, proof, block_index}
    block = ledger.get_block(rec.block_index)
    leaf  = leaf_hash(canonical_alert_bytes(alert))      # recompute from CURRENT data
    ok_leaf  = verify_proof(leaf, rec.proof, bytes.fromhex(rec.root))
    ok_block = (block.merkle_root == rec.root)
    chain_ok, bad = ledger.verify_chain()
    return {
      "alert_id": alert_id,
      "verified": bool(ok_leaf and ok_block and chain_ok),
      "anchored_at": block.timestamp,
      "block_index": block.index,
      "detail": "TAMPERED" if not (ok_leaf and ok_block) else
                ("CHAIN_BROKEN" if not chain_ok else "OK"),
    }

@app.get("/api/integrity/consistency")
def verify_ledger_consistency(since_sth_id: str):
    """Prove current ledger is an append-only extension of a previously
    published STH, without re-walking every block."""
    old_sth = sth_store.get(since_sth_id)
    new_sth = ledger.build_sth()
    proof = ledger.consistency_proof(old_sth.tree_size, new_sth.tree_size)
    ok = verify_consistency(old_sth.root_hash, old_sth.tree_size,
                             new_sth.root_hash, new_sth.tree_size, proof)
    return {"consistent": ok, "old_size": old_sth.tree_size,
            "new_size": new_sth.tree_size}
```

Dashboard: add a "Verify integrity" action on each alert row → ✅ green "Integrity verified — anchored 19:56:00, block #142" or ❌ red "TAMPERED / evidence altered."

Add a second panel: "Ledger consistency" showing the last externally-published STH and a green/red badge for whether the live ledger still consistency-proves against it.

Demo money-shot: during the presentation, manually edit an alert row in the DB (change the src IP or confidence), click Verify, and it turns red instantly. For the stronger demo, also manually edit a past ledger block and re-run consistency check against the externally-published STH — it turns red even if the whole local ledger was re-signed, because the external STH doesn't match. This visibly proves the difference between "tamper-evident against DB edits" and "tamper-evident against full host compromise."

### B.7 Public/external anchoring — now a core requirement, not optional
As established in §A.5, a locally-signed hash chain alone cannot detect an attacker who compromises the host and obtains the signing key. The mitigation is to publish the Signed Tree Head (STH) somewhere the NIDS operator does not fully control.

Recommended, in order of effort:

1. Simplest (free, no new dependency): commit the STH JSON (`tree_size`, `root_hash`, `timestamp`, `signature`) to a public GitHub repo/Gist on the daily cron. The git commit history itself becomes an external, timestamped witness.
2. Purpose-built (recommended): use OpenTimestamps — `pip install opentimestamps-client` and stamp the daily STH. An OpenTimestamps proof is a compact `.ots` file containing the Merkle path connecting the STH hash to a specific Bitcoin block header, and verification requires no trusted third party. This directly matches your batching design: OpenTimestamps calendar servers already aggregate many users' hashes per interval into one Merkle root, so you get the "one anchor per window" pattern for free.
3. Manual testnet OP_RETURN — viable but more code than #2 for the same guarantee.

Document this as the property that makes even the NIDS operator unable to rewrite history undetected — the same guarantee Guardtime KSI markets as "truth over trust," and the same reason Certificate Transparency requires external cosigners rather than trusting a single log operator's signature.

### B.8 Standardized proof format (Chainpoint-like)
Rather than inventing an ad hoc JSON shape for `{root, proof, block_index}`, structure it closer to the existing Chainpoint proof standard, which packages everything needed to independently verify an artifact's integrity — hash, Merkle path, and anchor reference — in one interoperable document. Adopting this shape costs nothing extra and lets the pitch claim standards-alignment rather than a bespoke format:

```python
# netsentinel/integrity/proof_schema.py
from dataclasses import dataclass

@dataclass
class IntegrityProof:
    type: str = "netsentinel-chainpoint-v1"
    alert_id: str = ""
    leaf_hash: str = ""            # hex
    merkle_proof: list = None      # [(sibling_hex, "L"|"R"), ...]
    merkle_root: str = ""          # hex
    block_index: int = 0
    block_hash: str = ""           # hex
    anchor_type: str = "local-ledger"   # or "opentimestamps", "git-commit"
    anchor_ref: str = ""           # e.g. OTS proof id, commit SHA
    timestamp: float = 0.0
```

### B.9 Config additions (config.py)

```yaml
integrity:
  enabled: true
  window_seconds: 60
  ledger_path: "netsentinel/integrity/ledger.jsonl"
  key_path:    "netsentinel/integrity/nid_ed25519.key"   # 0600 perms
  sth_interval_seconds: 86400        # daily STH
  external_anchor:
    enabled: true                    # was "public_anchor: false" (stretch) in v1 —
                                      # now on by default; see §B.7 rationale
    method: "opentimestamps"         # "git" | "opentimestamps" | "manual_testnet"
    git_repo: null                   # if method == "git"
```

### B.10 Dependencies
- `pynacl` (Ed25519 signing/verify).
- `opentimestamps-client` (optional but recommended, for §B.7 method #2).
- Everything else is stdlib (`hashlib`, `json`, `time`).

### B.11 Tests (tests/test_integrity.py)
1. Merkle correctness: build tree of N leaves; every leaf's proof verifies to root; a wrong leaf fails. Test N=1, even, odd.
2. Ledger linkage: append 5 blocks; `verify_chain()` returns `(True, None)`.
3. Tamper detection (alert): anchor an alert, then mutate it; verify endpoint returns `verified=False`, `detail="TAMPERED"`.
4. Tamper detection (ledger): flip a byte in a past block's `merkle_root`; `verify_chain()` returns `(False, that_index)`.
5. Batching/scale: anchor 10,000 alerts in one window ⇒ exactly ONE new block; all 10,000 proofs verify. (Proves throughput is decoupled from alert volume.)
6. NEW — consistency proof holds across growth: build STH at size 5, append 10 more blocks (size 15), consistency proof between size-5 root and size-15 root verifies true.
7. NEW — consistency proof detects rewritten history: same as #6, but mutate block #2 after the size-5 STH was taken (simulating full key compromise + re-sign); consistency proof against the externally-stored size-5 STH must fail even though a naive `verify_chain()` on the rewritten ledger alone would pass.

**Definition of done**: tests 1–7 pass; live-edit demo turns an alert red; one block is produced per window regardless of alert count; a rewritten-and-resigned ledger is still caught by consistency proof against a previously externally-published STH.

### B.12 Evidentiary-standards mapping (for docs/pitch, not code)

| NetSentinel artifact | Evidentiary property it supports |
|---|---|
| Canonical JSON + SHA-256 leaf hash | "Integrity confirmed via cryptographic hash" — the core FRE 901 / general admissibility ask |
| Ed25519 nid_pubkey + signature on each block | Maps to FRE 902(13)–(14) self-authentication of records generated by a reliable, documented process |
| merkle_root + prev_block_hash chain | Documented, reproducible chain-of-custody linkage across time |
| Externally-published STH (§B.7) | Independent verifiability without trusting the evidence holder — the property courts scrutinize (e.g., Hangzhou Internet Court's review of hash-chain integrity) and the property eIDAS-qualified timestamps are designed to guarantee |
| /api/integrity/verify + /api/integrity/consistency endpoints | Reproducible verification procedure an auditor/expert witness can run independently |

### B.13 Order of implementation (for the agent)

1. `merkle.py` + tests (get hashing/proofs exactly right first, including the consistency-proof helper).
2. `canonical.py` (byte-stable serialization).
3. `ledger.py` (Ed25519, append-only, verify_chain, build_sth, consistency_proof) + tests.
4. `anchor_service.py` (windowed batching + daily publish_sth) + proof store (off-chain).
5. Wire `add_alert` into the alert emission path; add the `flush()` and `publish_sth()` timers.
6. `proof_schema.py` (Chainpoint-like format).
7. `/api/integrity/verify/{alert_id}` + `/api/integrity/consistency` endpoints; dashboard Verify button + Ledger Consistency panel.
8. External anchoring integration (`opentimestamps-client` or git-commit method).
9. `docs/EVIDENTIARY_STANDARDS.md` (table from §B.12).

## PART C — HOW TO PITCH IT (judge-facing)
"We deliberately did NOT use blockchain to detect attacks — that misuses the technology. We use it for one thing it's genuinely good at: tamper-evident chain of custody for forensic evidence. Attackers routinely delete logs to cover tracks (MITRE T1070); our alerts are Merkle-batched and anchored to an append-only signed ledger, so any post-hoc tampering is cryptographically detectable. We anchor one Merkle root per window — not one transaction per alert — because on-chain logging caps around 70 TPS and grows linearly. That's the same batching model Guardtime's KSI uses to scale to national deployments in Estonia, and the same model Certificate Transparency uses to log every TLS certificate on the internet.

We also thought about the failure mode most projects ignore: what if the attacker compromises the signing key itself? A local hash-chain alone can't catch that — so we publish a daily Signed Tree Head externally and support Certificate-Transparency-style consistency proofs, so even a full host compromise that rewrites and re-signs our own ledger is still detectable against the externally-published record."

Four things this shows: you know the tech's real use, you know its limits, you tie it to industry and academic precedent, and you've reasoned about the threat model beyond the naive version (key compromise, not just DB edits). Keep the scope to chain-of-custody; do not expand into "blockchain threat-intel sharing" or "consensus detection" for a hackathon.

**Key changes vs. your original draft (summary for your own tracking):**
1. Added Certificate-Transparency-style **consistency proofs** and `SignedTreeHead` to `ledger.py` — closes the "ledger only proves internal linkage" gap.
2. Elevated external anchoring from **optional/stretch → core requirement** (§B.7), since it's the only defense against a fully compromised signing key; added OpenTimestamps as the recommended low-effort method.
3. Added a **Chainpoint-like standardized proof schema** (§B.8) instead of an ad hoc JSON shape.
4. Added **§A.6 / §B.12 evidentiary-standards mapping** (FRE 901/902, eIDAS, NIST SP 800-201, Hangzhou Internet Court precedent) to strengthen the legal/judge-facing justification.
5. Reinforced the anti-pattern argument with literature showing blockchain-in-IDS misuse is common, making your restraint a stronger differentiator.
6. Added two new tests (#6, #7) specifically proving the consistency-proof mechanism catches key-compromise-level tampering that plain chain-walking misses.