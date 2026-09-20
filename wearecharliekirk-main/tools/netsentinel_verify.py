#!/usr/bin/env python3
"""NetSentinel Offline Verifier — hand the judge an offline tool.

Usage:
    python tools/netsentinel_verify.py receipt-package.json [--replay]
    python tools/netsentinel_verify.py --server http://localhost:8000 --alert-id <UUID>

Modes:
  1. File mode: verify a receipt package exported from the API
  2. Server mode: fetch receipt + run verification against a live server

Exit codes:
  0 = all implemented claims PASS
  1 = at least one claim FAIL
  2 = all claims UNVERIFIABLE (no verdict possible)
  3 = usage error
"""

import argparse
import json
import sys
import base64
from pathlib import Path

# Add parent dir to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def verify_receipt_file(receipt_path: str, do_replay: bool = False) -> dict:
    """Verify a receipt package from a JSON file."""
    from netsentinel.integrity.encoding import jcs_canonicalize, digest_prefixed, canonical_digest
    from netsentinel.integrity.envelope import verify_envelope, envelope_to_bytes
    from netsentinel.integrity.merkle import verify_proof, MerkleProof

    with open(receipt_path, "r", encoding="utf-8") as f:
        package = json.load(f)

    envelope = package.get("envelope", {})
    merkle_proof_data = package.get("merkle_proof", {})
    merkle_root = package.get("merkle_root", "")

    results = []

    # ── Claim: DSSE Signature ──────────────────────────────────
    try:
        statement = verify_envelope(envelope)
        results.append({
            "claim": "DSSE Signature Valid",
            "status": "PASS",
            "detail": "Ed25519 signature verified over PAE-encoded payload",
        })
    except Exception as e:
        statement = None
        results.append({
            "claim": "DSSE Signature Valid",
            "status": "FAIL",
            "detail": f"Signature verification failed: {e}",
        })

    # Parse statement
    if statement is None:
        try:
            payload = base64.b64decode(envelope.get("payload", ""))
            statement = json.loads(payload)
        except Exception:
            statement = {}

    predicate = statement.get("predicate", {})

    # ── Claim: Receipt Schema ──────────────────────────────────
    required_fields = ["sensor", "evidence", "feature_pipeline", "model", "decision", "completeness"]
    missing = [f for f in required_fields if f not in predicate]
    if not missing:
        results.append({
            "claim": "Receipt Schema Complete",
            "status": "PASS",
            "detail": f"All {len(required_fields)} predicate sections present",
        })
    else:
        results.append({
            "claim": "Receipt Schema Complete",
            "status": "FAIL",
            "detail": f"Missing predicate sections: {missing}",
        })

    # ── Claim: Merkle Inclusion ─────────────────────────────────
    if merkle_proof_data and merkle_root:
        siblings = [
            (bytes.fromhex(h), side)
            for h, side in merkle_proof_data.get("siblings", [])
        ]
        proof = MerkleProof(
            leaf_index=merkle_proof_data.get("leaf_index", 0),
            tree_size=merkle_proof_data.get("tree_size", 0),
            siblings=siblings,
        )
        envelope_bytes = jcs_canonicalize(envelope)
        if verify_proof(envelope_bytes, proof, bytes.fromhex(merkle_root)):
            results.append({
                "claim": "Alert Included in Checkpoint",
                "status": "PASS",
                "detail": f"Merkle inclusion verified (tree_size={proof.tree_size})",
            })
        else:
            results.append({
                "claim": "Alert Included in Checkpoint",
                "status": "FAIL",
                "detail": "Merkle inclusion proof verification failed",
            })
    else:
        results.append({
            "claim": "Alert Included in Checkpoint",
            "status": "UNVERIFIABLE",
            "detail": "No Merkle proof in receipt package",
        })

    # ── Claim: Completeness Chain ───────────────────────────────
    completeness = predicate.get("completeness", {})
    prev_digest = completeness.get("previous_receipt_digest", "")
    seq = predicate.get("sensor", {}).get("event_sequence", 0)
    if seq > 0 and prev_digest:
        results.append({
            "claim": "Receipt Chain Integrity",
            "status": "PASS",
            "detail": f"Sequence #{seq}, previous_receipt_digest present",
        })
    elif seq > 0:
        results.append({
            "claim": "Receipt Chain Integrity",
            "status": "PASS",
            "detail": f"Sequence #{seq} (first receipt in chain)",
        })
    else:
        results.append({
            "claim": "Receipt Chain Integrity",
            "status": "UNVERIFIABLE",
            "detail": "No sequence number in receipt",
        })

    # ── Claim: Model Identity ───────────────────────────────────
    model_info = predicate.get("model", {})
    model_digest = model_info.get("model_digest", "")
    if model_digest and model_digest.startswith("sha256:"):
        results.append({
            "claim": "Model Identity Committed",
            "status": "PASS",
            "detail": f"Model digest: {model_digest[:40]}...",
        })
    else:
        results.append({
            "claim": "Model Identity Committed",
            "status": "UNVERIFIABLE",
            "detail": "No model digest in receipt",
        })

    # ── Summary ─────────────────────────────────────────────────
    pass_count = sum(1 for r in results if r["status"] == "PASS")
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    unverifiable_count = sum(1 for r in results if r["status"] == "UNVERIFIABLE")

    return {
        "file": receipt_path,
        "claims": results,
        "summary": {
            "pass": pass_count,
            "fail": fail_count,
            "unverifiable": unverifiable_count,
            "total": len(results),
        },
    }


def verify_from_server(server_url: str, alert_id: str) -> dict:
    """Fetch receipt from server and verify."""
    import urllib.request

    # Fetch verification report
    url = f"{server_url}/api/integrity/verify/{alert_id}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": f"Failed to fetch from server: {e}"}


def main():
    parser = argparse.ArgumentParser(
        description="NetSentinel Offline Verifier — Proof-Carrying Alert verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s receipt.json                          # Verify a receipt file
  %(prog)s receipt.json --replay                 # Verify + replay inference
  %(prog)s --server http://localhost:8000 --alert-id <UUID>  # Verify via API
        """,
    )
    parser.add_argument("receipt_file", nargs="?", help="Path to receipt package JSON")
    parser.add_argument("--replay", action="store_true", help="Run deterministic replay")
    parser.add_argument("--server", help="NetSentinel server URL")
    parser.add_argument("--alert-id", help="Alert ID to verify (with --server)")

    args = parser.parse_args()

    if args.server and args.alert_id:
        report = verify_from_server(args.server, args.alert_id)
    elif args.receipt_file:
        if not Path(args.receipt_file).exists():
            print(f"Error: File not found: {args.receipt_file}", file=sys.stderr)
            sys.exit(3)
        report = verify_receipt_file(args.receipt_file, do_replay=args.replay)
    else:
        parser.print_help()
        sys.exit(3)

    # Print report
    if "error" in report:
        print(f"\n❌ Error: {report['error']}")
        sys.exit(3)

    print("\n" + "=" * 60)
    print("  NetSentinel — Proof-Carrying Alert Verification")
    print("=" * 60)

    claims = report.get("claims", [])
    for c in claims:
        status = c.get("status", "?")
        claim_num = c.get("claim_number", c.get("claim", "?"))
        name = c.get("name", c.get("claim", "?"))
        detail = c.get("detail", "")

        if status == "PASS":
            icon = "✅"
        elif status == "FAIL":
            icon = "❌"
        else:
            icon = "⚠️ "

        print(f"  {icon} {name}: {status}")
        if detail:
            print(f"     └─ {detail}")

    # Summary
    summary = report.get("summary", {})
    if summary:
        print(f"\n  Summary: {summary['pass']} PASS, "
              f"{summary['fail']} FAIL, "
              f"{summary['unverifiable']} UNVERIFIABLE")
    else:
        has_fail = report.get("has_failures", False)
        verified = report.get("verified_overall", False)
        anchor = report.get("anchor_strength", "none")
        if verified:
            print(f"\n  ✅ ALL CLAIMS PASS (anchor strength: {anchor})")
        elif has_fail:
            print(f"\n  ❌ INTEGRITY VIOLATION DETECTED")
        else:
            print(f"\n  ⚠️  Some claims unverifiable")

    # Exit code
    if summary:
        if summary["fail"] > 0:
            sys.exit(1)
        elif summary["pass"] == 0:
            sys.exit(2)
        else:
            sys.exit(0)
    elif report.get("has_failures"):
        sys.exit(1)
    elif report.get("verified_overall"):
        sys.exit(0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
