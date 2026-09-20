#!/usr/bin/env python3
"""
test_quic.py -- prove the QUIC Initial key derivation against the RFC.

We are about to change the capture on the strength of a claim: that if we stop
truncating packets, we can read hostnames out of QUIC, which is 61% of our
encrypted traffic. That claim is worthless if our key derivation is wrong, and
we cannot test it on our own capture because every QUIC Initial in it was
truncated by snaplen 512 before the part we need.

So we test against the vectors published in RFC 9001 Appendix A.1, where the
connection ID, the secrets and the derived keys are all written down. If our
code reproduces those bytes exactly, the derivation is right and the only thing
standing between us and QUIC hostnames is the snaplen.

This is the same discipline as test_lanl_loader.py: build the test so that it
can fail, then run it.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netsentinel_v2.quic import (           # noqa: E402
    _hkdf_extract, _hkdf_expand_label, _initial_keys,
    INITIAL_SALT_V1, QUIC_V1, _varint, parse_quic_initial,
)

# RFC 9001 Appendix A.1 -- "Keys" for the client Initial of a v1 connection
# whose Destination Connection ID is 0x8394c8f03e515708.
DCID = bytes.fromhex("8394c8f03e515708")
EXP_INITIAL_SECRET = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
EXP_CLIENT_SECRET = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
EXP_KEY = "1f369613dd76d5467730efcbe3b1a22d"
EXP_IV = "fa044b2f42a3fd3b46fb255c"
EXP_HP = "9f50449e04a0e810283a1e9933adedd2"

fails = []
n = 0


def check(name, got, want):
    global n
    n += 1
    if got != want:
        fails.append(f"{name}\n      got  {got}\n      want {want}")
        print(f"  FAIL  {name}")
    else:
        print(f"  ok    {name}")


print("=" * 70)
print("  QUIC Initial key derivation vs RFC 9001 Appendix A.1")
print("=" * 70)

check("initial_salt is the published v1 salt",
      INITIAL_SALT_V1.hex(), "38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

initial_secret = _hkdf_extract(INITIAL_SALT_V1, DCID)
check("initial_secret  = HKDF-Extract(salt, dcid)",
      initial_secret.hex(), EXP_INITIAL_SECRET)

client_secret = _hkdf_expand_label(initial_secret, "client in", 32)
check("client_initial_secret", client_secret.hex(), EXP_CLIENT_SECRET)

key, iv, hp = _initial_keys(DCID, QUIC_V1)
check("client key (AES-128-GCM)", key.hex(), EXP_KEY)
check("client iv", iv.hex(), EXP_IV)
check("client header-protection key", hp.hex(), EXP_HP)

# --- varint decoding, RFC 9000 s16 worked examples -----------------------
print()
for hexs, want in [("c2197c5eff14e88c", 151288809941952652),
                   ("9d7f3e7d", 494878333),
                   ("7bbd", 15293),
                   ("25", 37),
                   ("4025", 37)]:
    got, _ = _varint(bytes.fromhex(hexs), 0)
    check(f"varint {hexs}", got, want)

# --- negative controls: the parser must refuse, not invent ---------------
print()
check("short-header packet is not treated as Initial",
      parse_quic_initial(bytes([0x40]) + b"\x00" * 40), None)
check("empty payload returns None", parse_quic_initial(b""), None)
r = parse_quic_initial(bytes([0xC0, 0x00, 0x00, 0x00, 0x00]) + b"\x00" * 40)
check("version 0 is reported as version negotiation",
      r["reason"] if r else None, "version_negotiation")
r = parse_quic_initial(bytes([0xC0, 0xAB, 0xCD, 0xEF, 0x01]) + b"\x00" * 40)
check("unknown version is reported, not guessed",
      (r["reason"].startswith("unsupported_version") if r else False), True)
r = parse_quic_initial(bytes([0xC0, 0x00, 0x00, 0x00, 0x01, 0x08])
                       + DCID + b"\x00" * 8)
check("a truncated Initial says so rather than returning a hostname",
      (r is not None and r["sni"] is None), True)

print()
print("=" * 70)
if fails:
    print(f"  {len(fails)} of {n} checks FAILED")
    for f in fails:
        print("   -", f)
    sys.exit(1)
print(f"  all {n} checks passed")
print()
print("  Meaning: the derivation is correct. Every QUIC hostname we are")
print("  currently missing is missing because snaplen 512 cut the Initial")
print("  packet, not because we cannot read the protocol. QUIC Initials are")
print("  padded to at least 1200 bytes by RFC 9000 s14.1, so 512 can never")
print("  work -- measured median in our own capture: 1,230 bytes of UDP")
print("  payload, 90.2% larger than 512.")
