"""RFC 8785 (JCS) canonicalization over a restricted value domain.

Value domain for ALL signed payloads (receipts, checkpoints, actions, releases):
  objects with string keys (sorted, no duplicates), arrays, str, int, bool, None.
  NO float.  NO NaN/Inf.  NO non-BMP-dependent ordering tricks.

Every signed artifact carries ``"canonicalization": "rfc8785-jcs-v1"`` and
``"schema_version"`` so a future migration is a format rotation, not a fork.

Replaces middle.md §B.3's ``json.dumps(sort_keys=True)`` with a deterministic,
cross-language-safe encoding profile that bans floats outright (Correction 4).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class CanonicalizationError(Exception):
    """Raised when a value outside the allowed domain is encountered."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def jcs_canonicalize(obj: Any) -> bytes:
    """Serialize *obj* to canonical UTF-8 bytes per RFC 8785 (JCS).

    Only the restricted NetSentinel value domain is accepted:
    str, int, bool, None, list, dict (string keys, sorted by UTF-16 code
    units).  **float is rejected** — a receipt containing a float is a bug.

    Returns:
        UTF-8 encoded canonical JSON bytes.

    Raises:
        CanonicalizationError: if a float or unsupported type is encountered.
    """
    assert_canonicalizable(obj)
    return _serialize(obj).encode("utf-8")


def assert_canonicalizable(obj: Any) -> None:
    """Walk *obj* and raise :class:`CanonicalizationError` on any float.

    Also rejects types outside the allowed domain (sets, bytes, custom
    objects, etc.).
    """
    _validate(obj, path="$")


def digest_prefixed(data: bytes) -> str:
    """Return ``"sha256:<hex>"`` digest of *data*.

    This is the **single digester** for the whole integrity system.
    """
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_bytes(data: bytes) -> bytes:
    """Return raw SHA-256 digest bytes of *data*."""
    return hashlib.sha256(data).digest()


def canonical_digest(obj: Any) -> str:
    """Convenience: JCS-canonicalize *obj* then return its prefixed digest."""
    return digest_prefixed(jcs_canonicalize(obj))


# ---------------------------------------------------------------------------
# RFC 8785 serialization (restricted domain)
# ---------------------------------------------------------------------------

# Escape map per RFC 8785 §3.2.2.2 — only these control characters and
# the two mandatory JSON escapes are represented as escape sequences.
_ESCAPE_MAP: dict[int, str] = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _escape_string(s: str) -> str:
    """Escape a string per RFC 8785 §3.2.2.2."""
    parts: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _ESCAPE_MAP:
            parts.append(_ESCAPE_MAP[cp])
        elif cp < 0x20:
            # Other C0 controls → \\u00XX
            parts.append(f"\\u{cp:04x}")
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _serialize(obj: Any) -> str:
    """Recursively serialize to a JCS-conformant JSON string."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int) and not isinstance(obj, bool):
        # Shortest decimal.  Python's str(int) already complies.
        # Lint-enforced range: ±2^53 (JS safe-integer range).
        if abs(obj) > 2**53:
            raise CanonicalizationError(
                f"Integer {obj} exceeds ±2^53 safe-integer range"
            )
        return str(obj)
    if isinstance(obj, str):
        return _escape_string(obj)
    if isinstance(obj, list):
        inner = ",".join(_serialize(item) for item in obj)
        return f"[{inner}]"
    if isinstance(obj, dict):
        # RFC 8785 §3.2.2: sort keys by UTF-16 code units.
        # For BMP-only strings this is identical to sorting by code point.
        sorted_keys = sorted(obj.keys(), key=_utf16_sort_key)
        inner = ",".join(
            f"{_escape_string(k)}:{_serialize(obj[k])}" for k in sorted_keys
        )
        return "{" + inner + "}"
    raise CanonicalizationError(
        f"Unsupported type {type(obj).__name__} at serialization"
    )


def _utf16_sort_key(s: str) -> list[int]:
    """Sort key for RFC 8785 object key ordering (UTF-16 code units)."""
    result: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            # Encode as surrogate pair
            cp -= 0x10000
            result.append(0xD800 + (cp >> 10))
            result.append(0xDC00 + (cp & 0x3FF))
        else:
            result.append(cp)
    return result


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate(obj: Any, path: str) -> None:
    """Recursively validate that *obj* is within the allowed domain."""
    if obj is None or isinstance(obj, bool):
        return
    if isinstance(obj, float):
        raise CanonicalizationError(
            f"float value {obj!r} at {path} — floats are banned from signed "
            f"payloads.  Convert to int (score_ppm) or RFC 3339 string."
        )
    if isinstance(obj, int):
        if abs(obj) > 2**53:
            raise CanonicalizationError(
                f"Integer {obj} at {path} exceeds ±2^53 safe-integer range"
            )
        return
    if isinstance(obj, str):
        return
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            _validate(item, f"{path}[{i}]")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"Non-string dict key {k!r} ({type(k).__name__}) at {path}"
                )
            _validate(v, f"{path}.{k}")
        return
    raise CanonicalizationError(
        f"Unsupported type {type(obj).__name__} at {path}"
    )


# ---------------------------------------------------------------------------
# Helpers for receipt assembly (float → int conversion at the boundary)
# ---------------------------------------------------------------------------

def confidence_to_ppm(confidence: float) -> int:
    """Convert a 0.0–1.0 confidence float to parts-per-million int.

    This is the ONLY place floats cross into the signed domain.
    The float never enters the receipt — only the integer does.
    """
    return int(round(confidence * 1_000_000))


def ppm_to_confidence(ppm: int) -> float:
    """Convert a parts-per-million int back to a 0.0–1.0 float.

    Used for display only — never inside signed payloads.
    """
    return ppm / 1_000_000
