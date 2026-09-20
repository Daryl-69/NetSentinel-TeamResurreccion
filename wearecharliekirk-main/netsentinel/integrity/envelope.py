"""DSSE (Dead Simple Signing Envelope) — in-repo implementation.

~80 lines.  Ed25519 via PyNaCl, no external ``securesystemslib``
dependency.  Keeps the project at stdlib + PyNaCl + FastAPI.

Spec: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md

PAE (Pre-Authentication Encoding):
    ``DSSEv1 <len(type)> <type> <len(body)> <body>``
where lengths are ASCII decimal and fields are space-separated.
"""

from __future__ import annotations

import base64
import json

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

from netsentinel.integrity.encoding import jcs_canonicalize


PAYLOAD_TYPE = "application/vnd.in-toto+json"


# ---------------------------------------------------------------------------
# PAE (Pre-Authentication Encoding)
# ---------------------------------------------------------------------------

def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding.

    ``DSSEv1 <len_type> <type> <len_body> <body>``
    """
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign_receipt(
    statement: dict,
    sk: SigningKey,
    *,
    payload_type: str = PAYLOAD_TYPE,
) -> dict:
    """Sign an in-toto statement as a DSSE envelope.

    Args:
        statement: the in-toto Statement v1 dict (will be JCS-canonicalized).
        sk: Ed25519 signing key.
        payload_type: DSSE payload type string.

    Returns:
        DSSE envelope dict with ``payloadType``, ``payload`` (base64),
        and ``signatures`` list.
    """
    payload = jcs_canonicalize(statement)
    pae = _pae(payload_type, payload)
    sig = sk.sign(pae).signature

    vk_hex = sk.verify_key.encode(encoder=HexEncoder).decode("ascii")

    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": vk_hex,
                "sig": base64.b64encode(sig).decode("ascii"),
            }
        ],
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_envelope(
    envelope: dict,
    vk: VerifyKey | None = None,
) -> dict:
    """Verify a DSSE envelope and return the parsed statement.

    If *vk* is ``None``, the verify key is extracted from the first
    signature's ``keyid`` field (self-verification — useful for demos,
    but a real deployment pins the expected key).

    Args:
        envelope: DSSE envelope dict.
        vk: optional pre-trusted verify key.

    Returns:
        Parsed in-toto statement dict.

    Raises:
        nacl.exceptions.BadSignatureError: if signature verification fails.
        ValueError: if the envelope is malformed.
    """
    payload_type = envelope["payloadType"]
    payload_b64 = envelope["payload"]
    sigs = envelope.get("signatures", [])

    if not sigs:
        raise ValueError("Envelope has no signatures")

    payload = base64.b64decode(payload_b64)
    pae = _pae(payload_type, payload)

    # Verify at least the first signature
    sig_entry = sigs[0]
    sig_bytes = base64.b64decode(sig_entry["sig"])

    if vk is None:
        keyid = sig_entry.get("keyid", "")
        vk = VerifyKey(keyid.encode("ascii"), encoder=HexEncoder)

    vk.verify(pae, sig_bytes)

    return json.loads(payload)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def envelope_digest(envelope: dict) -> str:
    """Compute the digest of a DSSE envelope for Merkle batching.

    The leaf hashed into the checkpoint is the digest of the *envelope*
    bytes (not the raw alert), per Correction 3.
    """
    from netsentinel.integrity.encoding import digest_prefixed
    canonical = jcs_canonicalize(envelope)
    return digest_prefixed(canonical)


def envelope_to_bytes(envelope: dict) -> bytes:
    """Canonical bytes of the envelope for hashing / storage."""
    return jcs_canonicalize(envelope)
