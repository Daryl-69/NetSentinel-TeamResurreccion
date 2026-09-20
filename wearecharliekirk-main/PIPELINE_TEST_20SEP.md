# Full-pipeline test — 20 September 2026

*Everything below was executed against `wearecharliekirk-main` on Deep's machine,
on **real captured traffic** (200 MB / 186,363 packets from `D:\capture`), not
simulated input. Every number is measured. Where something could not be run, the
reason is stated rather than the result assumed.*

## Verdict

**Not industrial-grade yet.** Three blockers, in order of seriousness:

1. **The append-only proof does not work** — the tamper-evident ledger cannot
   prove the log wasn't rewritten (§4). Broken in shipped code.
2. **The detection half cannot run in a restricted network** — the six models
   are not in the repo and download from HuggingFace at import (§1).
3. **~42 Mbps single-threaded** on real traffic — fine for an OT/SCADA link,
   ~4% of a 1 GbE enterprise link (§3).

What *is* solid: the extractor runs clean on real traffic, the Merkle inclusion
proofs are correct including tamper rejection, and the signed block chain verifies.

---

## 1. Models are not in the repo — and that is a design problem here

`netsentinel/config.py:8` resolves all six ONNX experts from
`HF_REPO_ID = "Unded-17/netsentinel-models"` at **import time**. Nothing is
vendored except `portscan_spsd_decisiontree.pkl` (2.6 KB).

HuggingFace is unreachable from both environments I can execute in (HTTP 403 at
the proxy). Result:

```
[INFO]  Model not found locally, downloading from Hugging Face: Ddos_detection/ddos_binary_xgboost.onnx
[ERROR] Failed to download ...: 403 Forbidden
```

**Correction (same day).** An earlier version of this report said `config.py`
"prints the error and continues rather than failing hard". **That was wrong.**
Re-checked: `from netsentinel import config` exits 1 and `import
netsentinel.main` exits 1 — it raises and refuses to start, which is the correct
behaviour for a security product. The printed `[ERROR]` lines are the exception
propagating, not a swallowed failure.

**Why this matters beyond my sandbox:** NetSentinel is pitched at air-gapped
networks behind data diodes. A first run that requires an outbound internet
fetch is the one thing such a site cannot do. **Addressed 20 Sep:** models now
resolve from `$NETSENTINEL_MODELS_DIR` or `<repo>/models/` before any network
call, so a site can be given an offline bundle.

## 2. Test suite

| what | result |
|---|---|
| `python tests/test_extractor.py` (with `PYTHONPATH=.`) | **exit 0** |
| `pytest tests/` | **INTERNALERROR — collection aborts** |
| targeted `pytest` on the 5 real test modules | **7 passed, 7 failed, 14 skipped** |

- All **7 failures are `httpx.ProxyError` (the HF block)** — environment, not logic.
- `pytest tests/` dies entirely because **`tests/test_advanced.py` calls
  `sys.exit(1)` at module import**; pytest cannot collect the directory. Scripts
  and pytest modules are mixed in `tests/`.
- Tests don't put the repo root on `sys.path`, so `python tests/x.py` fails with
  `ModuleNotFoundError: No module named 'netsentinel'` unless `PYTHONPATH` is set.
- **`pytest` is not in `requirements.txt`.**

## 3. Throughput on real traffic — measured

Input: `ns_00001_20260918083538.pcap`, 200 MB, 186,363 packets of real capture.

| | measured |
|---|---|
| full extract (pcap → flow events) | **38.52 s** |
| flow events produced | 2,299 |
| **packet rate** | **4,840 pkt/s** |
| **byte rate** | **5.2 MB/s ≈ 42 Mbps** |
| peak RSS | 128 MB |
| raw `scapy` read alone (same file) | 4.1 s → 45,406 pkt/s |

**The bottleneck is feature extraction, not packet reading:** reading costs 4.1 s
of the 38.5 s (**11%**); the other **89%** is the extractor. Optimising the pcap
reader would buy almost nothing.

**Honest context:** 42 Mbps is roughly **4% of a 1 GbE link** and 0.4% of 10 GbE.
For the OT/SCADA and diode links this product targets — often ≤100 Mbps — it is
plausibly adequate. For an enterprise core it is not, and "42 Mbps, single
process" is the number to quote, not "real-time".

**Also:** `cicflowmeter` is absent and not in `requirements.txt`, so the
extractor **silently falls back**:

```
CICFlowMeter not available, falling back to custom: cicflowmeter not installed.
```

That fallback is exactly the path behind the documented 92% feature drift. A
silent switch between two feature implementations is a correctness hazard —
make it loud, or pin one.

## 4. Integrity subsystem — the real bug

All 9 modules import. Two of three properties hold.

**Works — Merkle inclusion:**

```
all 8 inclusion proofs verify   -> True
tampered alert verifies?        -> False   (correct)
wrong root verifies?            -> False   (correct)
```

**Works — signed block chain:** 5 blocks appended, Ed25519 signed,
`verify_chain() -> (True, None)`.

**Broken — Merkle consistency (append-only proof):**

```
 old -> new   proof_len   verifies
   1 -> 2         1        False
   2 -> 3         1        False
   2 -> 4         1        False
   3 -> 4         3        False
   4 -> 5         1        False
   4 -> 8         1        False
   5 -> 8         4        False
   8 -> 9         1        False
   8 -> 16        1        False
   7 -> 9         5        False
```

**Ten of ten fail, including the trivial 1→2 case.** Proofs are generated
(non-empty); verification never succeeds.

**Root cause** — `netsentinel/integrity/merkle.py`, `verify_consistency()`:

```python
if _is_power_of_two(old_size):
    fr = proof[0]          # <-- discards old_root
    sr = proof[0]
    idx = 1
...
return fr == old_root and sr == new_root
```

`fr` is supposed to be the *reconstructed* old root, compared against the
supplied `old_root`. But when `old_size` is a power of two it is overwritten with
`proof[0]` (the right-subtree sibling), and in the other branch it is mutated by
`_node(fr, node)`. Either way the final `fr == old_root` test cannot pass for a
genuine append. Per RFC 6962 §2.1.2, when the old tree is a complete subtree the
verifier consumes **no** proof node for it — `fr` should start as `old_root` and
stay untouched on that path.

This is **not dead code**: `ledger.py:29-30` imports it and `ledger.py:327` calls
it, and the frontend ships `IntegrityVerifyPanel.tsx`.

**Consequence, stated plainly:** the ledger can prove *"this alert is in the
log"* but **cannot prove *"the log has only been appended to"***. For a
tamper-evident audit trail aimed at nuclear/defence, append-only is the property
that matters. Do not demo or claim consistency proofs until this is fixed.

## 5. Version pinning

`requirements.txt` pins `scikit-learn==1.3.2`; the environment had 1.7.2, and the
port-scan model loads anyway with:

```
InconsistentVersionWarning: Trying to unpickle estimator DecisionTreeClassifier
from version 1.3.2 when using version 1.7.2. This might lead to breaking code or
invalid results.
```

It loaded and produced an object, so nothing fails visibly. This is the same
class of defect as the documented exfil-VAE false-positive rate. Either enforce
the pin at startup or re-serialise the models under the supported version.

## 6. What was not tested, and why

| not tested | reason |
|---|---|
| Model inference for the 6 experts | models unobtainable (§1) |
| End-to-end alert → WebSocket → dashboard | needs the models and a running server |
| Detection accuracy / FP rate on labelled data | needs the models |
| Exfil-VAE false-positive rate | needs the models |
| Frontend | not exercised |

**No accuracy claim of any kind can be made from this run.** Throughput,
extraction and integrity were tested; detection was not.

## 7. Fix list, in the order I would do it

1. **`verify_consistency()`** — reconstruct the old root per RFC 6962 instead of
   overwriting it. Add the 1→2 / 4→8 / 7→9 cases as regression tests.
2. ~~**Vendor the models**~~ — **done 20 Sep.** `get_model_path()` now resolves
   in this order: `$NETSENTINEL_MODELS_DIR` → `<repo>/models/` → the two legacy
   paths → HuggingFace. An air-gapped site can be handed a model bundle out of
   band and never touch the network. (It already failed hard on a missing model;
   see the correction in §1.)
3. **Make the CICFlowMeter fallback loud** (log at ERROR, or refuse to start in
   a mode that expects it).
4. **`tests/`**: move scripts out, add `pytest` to requirements, add a
   `conftest.py` that puts the repo root on `sys.path`.
5. **Enforce the sklearn pin** at startup, or re-serialise the `.pkl`.
6. **Throughput**: the extractor is 89% of the cost. If enterprise line rate is a
   goal, that is the only thing worth profiling.

---

*Tier‑2 (`tier2/`) was verified separately and is green: 8/8 suites, 25 numbers
re-derived, on the same day. See `tier2/HOW_THIS_FITS.md`.*
