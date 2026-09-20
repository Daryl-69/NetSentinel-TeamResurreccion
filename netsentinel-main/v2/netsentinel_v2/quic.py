"""
netsentinel_v2.quic -- read the hostname out of a QUIC handshake.

Why this exists
---------------
Our first capture audit reported that 61% of encrypted traffic was QUIC and
treated that as traffic we could not see into, and the proposed fix was to turn
QUIC off in the browser with a registry policy. That was wrong on the
engineering and bad for the pitch.

QUIC Initial packets are protected with keys derived from a SALT PUBLISHED IN
THE RFC (RFC 9001 s5.2) and the client's own Destination Connection ID, which
travels in cleartext in the same packet. Anyone who can see the packet can
derive the key. This is not an attack and it is not TLS interception -- it is
the documented design, and it exists so that middleboxes and monitoring can
still read the handshake. The client's first flight carries the TLS
ClientHello, and therefore the SNI.

So a passive sensor CAN name QUIC flows. We do that here instead of disabling
the protocol, which means:
  * our capture stops being an artificial environment nobody runs in production
  * the 61% becomes visible rather than discarded
  * we can honestly say "we parse QUIC" instead of "we switched QUIC off"

What this does NOT give us
--------------------------
  * Anything after the handshake. Application data uses keys derived from the
    TLS key exchange, which we cannot compute passively. We read the hostname
    and nothing else. That is the same posture we have for TLS over TCP.
  * A hostname when Encrypted Client Hello is in use. With ECH the outer SNI is
    a cover name (typically the provider's). We detect and report ECH rather
    than silently recording the cover name as the truth -- see `ech` in the
    result.
  * QUIC versions other than v1 (RFC 9000) and the draft salts. Version
    negotiation packets and unknown versions are reported as such, not guessed.

Reference: RFC 9000 (transport), RFC 9001 (TLS/QUIC, key derivation s5.2,
header protection s5.4).
"""
from __future__ import annotations

import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# RFC 9001 s5.2 -- the initial salt for QUIC version 1. Published, fixed.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_V1 = 0x00000001
# QUIC v2 (RFC 9369) uses a different salt and different label constants.
INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
QUIC_V2 = 0x6B3343CF


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    import hmac
    import hashlib
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 s7.1) as QUIC uses it."""
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
                      info=info).derive(secret)


def _varint(buf: bytes, off: int) -> Tuple[int, int]:
    """RFC 9000 s16 variable-length integer. Returns (value, new_offset)."""
    if off >= len(buf):
        raise ValueError("varint past end")
    b0 = buf[off]
    n = 1 << (b0 >> 6)
    if off + n > len(buf):
        raise ValueError("varint truncated")
    val = b0 & 0x3F
    for i in range(1, n):
        val = (val << 8) | buf[off + i]
    return val, off + n


def _initial_keys(dcid: bytes, version: int) -> Tuple[bytes, bytes, bytes]:
    """Derive the CLIENT initial key, iv and header-protection key."""
    if version == QUIC_V2:
        salt = INITIAL_SALT_V2
        k_lbl, iv_lbl, hp_lbl = "quicv2 key", "quicv2 iv", "quicv2 hp"
    else:
        salt = INITIAL_SALT_V1
        k_lbl, iv_lbl, hp_lbl = "quic key", "quic iv", "quic hp"
    initial_secret = _hkdf_extract(salt, dcid)
    client_secret = _hkdf_expand_label(initial_secret, "client in", 32)
    key = _hkdf_expand_label(client_secret, k_lbl, 16)
    iv = _hkdf_expand_label(client_secret, iv_lbl, 12)
    hp = _hkdf_expand_label(client_secret, hp_lbl, 16)
    return key, iv, hp


def _remove_header_protection(pkt: bytes, pn_off: int, hp: bytes):
    """RFC 9001 s5.4. Returns (first_byte, pn_len, packet_number_bytes)."""
    sample_off = pn_off + 4
    sample = pkt[sample_off:sample_off + 16]
    if len(sample) < 16:
        raise ValueError("packet too short for HP sample")
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first = pkt[0] ^ (mask[0] & 0x0F)          # long header: low 4 bits
    pn_len = (first & 0x03) + 1
    pn = bytes(pkt[pn_off + i] ^ mask[1 + i] for i in range(pn_len))
    return first, pn_len, pn


def _parse_client_hello_sni(ch: bytes) -> Tuple[Optional[str], bool]:
    """Given TLS handshake bytes starting at the ClientHello, return
    (sni, ech_present). Returns (None, ...) if it cannot be read."""
    try:
        if not ch or ch[0] != 0x01:
            return None, False
        # handshake header: type(1) len(3)
        body = ch[4:]
        off = 2 + 32                      # legacy_version + random
        sid_len = body[off]
        off += 1 + sid_len
        cs_len = struct.unpack("!H", body[off:off + 2])[0]
        off += 2 + cs_len
        comp_len = body[off]
        off += 1 + comp_len
        ext_total = struct.unpack("!H", body[off:off + 2])[0]
        off += 2
        end = off + ext_total
        sni, ech = None, False
        while off + 4 <= min(end, len(body)):
            etype, elen = struct.unpack("!HH", body[off:off + 4])
            off += 4
            edata = body[off:off + elen]
            if etype == 0x0000 and len(edata) >= 5:          # server_name
                # list_len(2) type(1) name_len(2) name
                nlen = struct.unpack("!H", edata[3:5])[0]
                name = edata[5:5 + nlen]
                if len(name) == nlen:
                    sni = name.decode("idna", errors="replace") \
                        if False else name.decode("utf-8", errors="replace")
            elif etype == 0xFE0D:                            # encrypted_client_hello
                ech = True
            off += elen
        return sni, ech
    except Exception:
        return None, False


def parse_quic_initial(udp_payload: bytes) -> Optional[dict]:
    """
    Try to read a client QUIC Initial packet and return
        {"sni": str|None, "ech": bool, "version": int, "dcid": hex, "ok": bool,
         "reason": str}
    or None when this is not a long-header QUIC packet at all.

    Only CLIENT Initial packets carry the ClientHello, so a server Initial will
    simply fail to decrypt with the client keys and is reported, not guessed.
    """
    if len(udp_payload) < 7:
        return None
    first = udp_payload[0]
    if not (first & 0x80):
        return None                       # short header: application data
    if not (first & 0x40):
        return None                       # fixed bit clear: not QUIC v1/v2
    version = struct.unpack("!I", udp_payload[1:5])[0]
    if version == 0:
        return {"sni": None, "ech": False, "version": 0, "dcid": "",
                "ok": False, "reason": "version_negotiation"}
    if version not in (QUIC_V1, QUIC_V2):
        return {"sni": None, "ech": False, "version": version, "dcid": "",
                "ok": False, "reason": f"unsupported_version_{version:#x}"}

    # long header packet type: v1 Initial == 0b00, v2 Initial == 0b01
    ptype = (first & 0x30) >> 4
    want = 0 if version == QUIC_V1 else 1
    if ptype != want:
        return {"sni": None, "ech": False, "version": version, "dcid": "",
                "ok": False, "reason": "not_initial"}

    try:
        off = 5
        dcid_len = udp_payload[off]; off += 1
        dcid = udp_payload[off:off + dcid_len]; off += dcid_len
        scid_len = udp_payload[off]; off += 1
        off += scid_len
        token_len, off = _varint(udp_payload, off)
        off += token_len
        length, off = _varint(udp_payload, off)
        pn_off = off
        if pn_off + length > len(udp_payload):
            return {"sni": None, "ech": False, "version": version,
                    "dcid": dcid.hex(), "ok": False,
                    "reason": "truncated_by_snaplen"}

        key, iv, hp = _initial_keys(dcid, version)
        firstb, pn_len, pn = _remove_header_protection(udp_payload, pn_off, hp)

        header = bytearray(udp_payload[:pn_off + pn_len])
        header[0] = firstb
        header[pn_off:pn_off + pn_len] = pn
        payload = udp_payload[pn_off + pn_len:pn_off + length]

        pn_int = int.from_bytes(pn, "big")
        nonce = bytearray(iv)
        pnb = pn_int.to_bytes(12, "big")
        nonce = bytes(a ^ b for a, b in zip(nonce, pnb))

        plain = AESGCM(key).decrypt(nonce, payload, bytes(header))
    except Exception as e:
        return {"sni": None, "ech": False, "version": version, "dcid": "",
                "ok": False, "reason": f"decrypt_failed:{type(e).__name__}"}

    # Walk frames, collect CRYPTO data by offset (the ClientHello can be split
    # across several CRYPTO frames even inside one packet).
    chunks = {}
    i = 0
    try:
        while i < len(plain):
            ftype, i = _varint(plain, i)
            if ftype == 0x00:                       # PADDING
                continue
            if ftype == 0x01:                       # PING
                continue
            if ftype == 0x06:                       # CRYPTO
                c_off, i = _varint(plain, i)
                c_len, i = _varint(plain, i)
                chunks[c_off] = plain[i:i + c_len]
                i += c_len
                continue
            if ftype == 0x02 or ftype == 0x03:      # ACK
                break
            break                                    # anything else: stop
    except Exception:
        pass

    if not chunks:
        return {"sni": None, "ech": False, "version": version,
                "dcid": dcid.hex(), "ok": False, "reason": "no_crypto_frame"}

    crypto = b""
    for o in sorted(chunks):
        if o == len(crypto):
            crypto += chunks[o]
    sni, ech = _parse_client_hello_sni(crypto)
    return {"sni": sni, "ech": ech, "version": version, "dcid": dcid.hex(),
            "ok": sni is not None,
            "reason": "ok" if sni else ("ech" if ech else "no_sni_in_first_packet")}
