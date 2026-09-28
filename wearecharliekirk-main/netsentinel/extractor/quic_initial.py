"""QUIC v1 Initial packets -> ClientHello (OFF by default).

A QUIC client's ClientHello travels inside its Initial packets. Unlike TLS
over TCP it is not in the clear: the Initial packets are protected with keys
derived from the Destination Connection ID in the packet header, using a
salt published in RFC 9001 s5.2. The keys are public -- any observer can
compute them, which is how Wireshark, Zeek and the JA4 tools read QUIC
ClientHellos -- but reading the ClientHello still means running a
decryption. PS 26145 constraint (b) says "no payload decryption", so this
module only runs when QUIC_INITIAL_PARSE is switched on (see config.py).

What it touches when enabled: the client's first Initial packets of a flow
(at most 4 datagrams), only the CRYPTO frames in them, only to read the
ClientHello. Handshake and 1-RTT packets use keys the sensor does not have
and are never decrypted. With the switch off, QUIC flows are still analysed
from their sizes and timing like any other UDP flow.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Optional

QUIC_V1 = 0x00000001
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
MAX_DATAGRAMS = 4
MAX_CRYPTO_BYTES = 16384


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def client_initial_keys(dcid: bytes):
    """(key, iv, hp) protecting the client's Initial packets (RFC 9001 s5.2)."""
    initial = _hkdf_extract(INITIAL_SALT_V1, dcid)
    secret = _hkdf_expand_label(initial, b"client in", 32)
    return (_hkdf_expand_label(secret, b"quic key", 16),
            _hkdf_expand_label(secret, b"quic iv", 12),
            _hkdf_expand_label(secret, b"quic hp", 16))


def _varint(b: bytes, o: int):
    if o >= len(b):
        raise ValueError("short")
    first = b[o]
    n = 1 << (first >> 6)
    if o + n > len(b):
        raise ValueError("short")
    v = first & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[o + i]
    return v, o + n


def is_client_initial(datagram: bytes) -> bool:
    return (len(datagram) >= 7 and (datagram[0] & 0xC0) == 0xC0
            and int.from_bytes(datagram[1:5], "big") == QUIC_V1
            and ((datagram[0] >> 4) & 0x03) == 0)


def decrypt_client_initial(datagram: bytes):
    """Remove header protection and open the first Initial packet.

    Returns (dcid, plaintext frames) or None if this is not a v1 client
    Initial or it does not authenticate.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:          # pragma: no cover - cryptography is a dependency
        return None
    if not is_client_initial(datagram):
        return None
    b = datagram
    try:
        o = 5
        dl = b[o]; o += 1
        dcid = bytes(b[o:o + dl]); o += dl
        sl = b[o]; o += 1 + sl
        tok_len, o = _varint(b, o); o += tok_len
        length, o = _varint(b, o)
    except (ValueError, IndexError):
        return None
    pn_off = o
    if pn_off + 20 > len(b) or pn_off + length > len(b):
        return None
    key, iv, hp = client_initial_keys(dcid)
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(bytes(b[pn_off + 4: pn_off + 20])) + enc.finalize()
    first = b[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b[pn_off + i] ^ mask[1 + i] for i in range(pn_len))
    header = bytes([first]) + bytes(b[1:pn_off]) + pn_bytes
    nonce = bytes(x ^ y for x, y in zip(iv, int.from_bytes(pn_bytes, "big").to_bytes(12, "big")))
    try:
        plain = AESGCM(key).decrypt(nonce, bytes(b[pn_off + pn_len: pn_off + length]), header)
    except Exception:
        return None
    return dcid, plain


def crypto_frames(plain: bytes) -> list:
    """(offset, data) of every CRYPTO frame; other Initial frames skipped."""
    out, o = [], 0
    try:
        while o < len(plain):
            ft, o = _varint(plain, o)
            if ft in (0x00, 0x01):                 # PADDING, PING
                continue
            if ft in (0x02, 0x03):                 # ACK (+ECN)
                _, o = _varint(plain, o); _, o = _varint(plain, o)
                rc, o = _varint(plain, o); _, o = _varint(plain, o)
                for _ in range(rc):
                    _, o = _varint(plain, o); _, o = _varint(plain, o)
                if ft == 0x03:
                    for _ in range(3):
                        _, o = _varint(plain, o)
                continue
            if ft == 0x06:                         # CRYPTO
                off, o = _varint(plain, o)
                ln, o = _varint(plain, o)
                out.append((off, bytes(plain[o:o + ln])))
                o += ln
                continue
            break                                  # anything else: stop reading
    except ValueError:
        pass
    return out


class QuicHelloAssembler:
    """Reassembles the CRYPTO stream of one flow's client Initials."""

    def __init__(self):
        self.chunks: dict[int, bytes] = {}
        self.datagrams = 0
        self.done = False

    def feed(self, datagram: bytes) -> Optional[bytes]:
        """Returns the ClientHello handshake body once complete, else None."""
        from netsentinel.extractor.tls_parse import handshake_message, HS_CLIENT_HELLO
        if self.done or self.datagrams >= MAX_DATAGRAMS:
            self.done = True
            return None
        self.datagrams += 1
        opened = decrypt_client_initial(datagram)
        if opened is None:
            return None
        for off, data in crypto_frames(opened[1]):
            if off < MAX_CRYPTO_BYTES:
                self.chunks[off] = data
        stream, pos = bytearray(), 0
        for off in sorted(self.chunks):
            if off > pos:
                break
            seg = self.chunks[off]
            if off + len(seg) > pos:
                stream += seg[pos - off:]
                pos = off + len(seg)
        status, body = handshake_message(bytes(stream), HS_CLIENT_HELLO)
        if status == "ok":
            self.done = True
            return body
        if status == "not_tls":
            self.done = True
        return None
