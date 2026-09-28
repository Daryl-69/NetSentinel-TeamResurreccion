"""TLS handshake metadata: ClientHello / ServerHello parsing, JA3, JA3S, JA4.

PS 26145 constraint (b) -- no payload decryption, TLS/QUIC metadata only.
Everything here reads the handshake messages that TLS sends in the clear
before any key exists: the ClientHello (offered versions, cipher suites,
extensions, SNI, ALPN, groups, signature algorithms) and the ServerHello
(chosen version, cipher and extensions). Application data is never touched
and nothing is decrypted.

Fingerprints:
  JA3  md5("version,ciphers,extensions,groups,point_formats"), decimal
       values joined with "-", GREASE values removed (Salesforce, 2017).
  JA3S md5("version,cipher,extensions") of the ServerHello.
  JA4  FoxIO's format: a_b_c where
       a = t|q (TCP or QUIC), TLS version, d|i (SNI or not), 2-digit cipher
           count, 2-digit extension count, first+last char of the first ALPN
       b = sha256 of the sorted cipher list (4-hex, comma-joined)[:12]
       c = sha256 of the sorted extension list without SNI and ALPN, then
           "_" and the signature algorithms in wire order[:12]
       Checked in tests/test_tls_fingerprints.py against the worked example
       published with the JA4 specification.
"""
from __future__ import annotations

import hashlib
from typing import Optional

TLS_HANDSHAKE = 22
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
MAX_HELLO_BYTES = 16384 + 5

EXT_SNI = 0x0000
EXT_GROUPS = 0x000A
EXT_POINT_FORMATS = 0x000B
EXT_SIG_ALGS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ECH = 0xFE0D

_JA4_VERSION = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
                0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}
_VERSION_NAME = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1", 0x0301: "TLS 1.0",
                 0x0300: "SSL 3.0"}


def is_grease(v: int) -> bool:
    """RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


class _Reader:
    __slots__ = ("b", "o", "end")

    def __init__(self, b, o=0, end=None):
        self.b, self.o, self.end = b, o, len(b) if end is None else end

    def u8(self):
        if self.o + 1 > self.end: raise ValueError("short")
        v = self.b[self.o]; self.o += 1; return v

    def u16(self):
        if self.o + 2 > self.end: raise ValueError("short")
        v = (self.b[self.o] << 8) | self.b[self.o + 1]; self.o += 2; return v

    def u24(self):
        if self.o + 3 > self.end: raise ValueError("short")
        v = (self.b[self.o] << 16) | (self.b[self.o + 1] << 8) | self.b[self.o + 2]; self.o += 3; return v

    def take(self, n):
        if n < 0 or self.o + n > self.end: raise ValueError("short")
        v = self.b[self.o:self.o + n]; self.o += n; return bytes(v)

    def left(self):
        return self.end - self.o


# --------------------------------------------------------------------------
# Record layer (TCP): collect one handshake message out of the byte stream
# --------------------------------------------------------------------------
def extract_handshake(buf: bytes, want_type: int):
    """Pull the first handshake message out of the start of a TLS stream.

    Returns ("ok", body) | ("need_more", None) | ("not_tls", None).
    Handles a message split over several TCP segments and over several TLS
    records. Stops at the first non-handshake record.
    """
    hs = bytearray()
    off = 0
    n = len(buf)
    while True:
        if n - off < 5:
            return ("need_more", None) if n < MAX_HELLO_BYTES else ("not_tls", None)
        ctype, vmaj = buf[off], buf[off + 1]
        rlen = (buf[off + 3] << 8) | buf[off + 4]
        if ctype != TLS_HANDSHAKE or vmaj != 3 or rlen == 0 or rlen > 18432:
            return ("not_tls", None)
        chunk = buf[off + 5: off + 5 + rlen]
        hs += chunk
        if len(hs) >= 4:
            if hs[0] != want_type:
                return ("not_tls", None)
            mlen = (hs[1] << 16) | (hs[2] << 8) | hs[3]
            if mlen > 65536:
                return ("not_tls", None)
            if len(hs) >= 4 + mlen:
                return ("ok", bytes(hs[4:4 + mlen]))
        if len(chunk) < rlen:          # record not complete yet
            return ("need_more", None) if n < MAX_HELLO_BYTES else ("not_tls", None)
        off += 5 + rlen


def handshake_message(data: bytes, want_type: int):
    """For QUIC: the CRYPTO stream carries bare handshake messages (no records)."""
    if len(data) < 4:
        return ("need_more", None)
    if data[0] != want_type:
        return ("not_tls", None)
    mlen = (data[1] << 16) | (data[2] << 8) | data[3]
    if len(data) < 4 + mlen:
        return ("need_more", None)
    return ("ok", bytes(data[4:4 + mlen]))


# --------------------------------------------------------------------------
# Hello parsing
# --------------------------------------------------------------------------
def parse_client_hello(body: bytes) -> Optional[dict]:
    try:
        r = _Reader(body)
        legacy_version = r.u16()
        r.take(32)                                  # random
        r.take(r.u8())                              # session id
        cs_len = r.u16()
        if cs_len % 2:
            return None
        cs = _Reader(r.take(cs_len))
        ciphers = [cs.u16() for _ in range(cs_len // 2)]
        r.take(r.u8())                              # compression methods
        ch = {"legacy_version": legacy_version, "ciphers": ciphers, "extensions": [],
              "sni": None, "sni_present": False, "groups": [], "point_formats": [],
              "sig_algs": [], "alpn": [], "alpn_raw": [], "supported_versions": [],
              "ech": False}
        if r.left() < 2:
            return ch
        ext_total = r.u16()
        er = _Reader(r.take(min(ext_total, r.left())))
        while er.left() >= 4:
            et = er.u16()
            data = er.take(er.u16())
            ch["extensions"].append(et)
            d = _Reader(data)
            try:
                if et == EXT_SNI:
                    ch["sni_present"] = True
                    lst = _Reader(d.take(d.u16()))
                    while lst.left() >= 3:
                        ntype = lst.u8(); name = lst.take(lst.u16())
                        if ntype == 0 and ch["sni"] is None:
                            ch["sni"] = name.decode("ascii", "replace")
                elif et == EXT_GROUPS:
                    n = d.u16(); g = _Reader(d.take(n))
                    ch["groups"] = [g.u16() for _ in range(n // 2)]
                elif et == EXT_POINT_FORMATS:
                    n = d.u8(); ch["point_formats"] = list(d.take(n))
                elif et == EXT_SIG_ALGS:
                    n = d.u16(); s = _Reader(d.take(n))
                    ch["sig_algs"] = [s.u16() for _ in range(n // 2)]
                elif et == EXT_ALPN:
                    lst = _Reader(d.take(d.u16()))
                    while lst.left() >= 1:
                        p = lst.take(lst.u8())
                        ch["alpn_raw"].append(p)
                        ch["alpn"].append(p.decode("ascii", "replace"))
                elif et == EXT_SUPPORTED_VERSIONS:
                    n = d.u8(); v = _Reader(d.take(n))
                    ch["supported_versions"] = [v.u16() for _ in range(n // 2)]
                elif et == EXT_ECH:
                    ch["ech"] = True
            except ValueError:
                continue                           # malformed extension body: keep the type
        return ch
    except ValueError:
        return None


def parse_server_hello(body: bytes) -> Optional[dict]:
    try:
        r = _Reader(body)
        legacy_version = r.u16()
        r.take(32)
        r.take(r.u8())
        cipher = r.u16()
        r.u8()                                      # compression
        sh = {"legacy_version": legacy_version, "cipher": cipher, "extensions": [],
              "selected_version": None, "alpn": None}
        if r.left() >= 2:
            er = _Reader(r.take(min(r.u16(), r.left())))
            while er.left() >= 4:
                et = er.u16(); data = er.take(er.u16())
                sh["extensions"].append(et)
                d = _Reader(data)
                try:
                    if et == EXT_SUPPORTED_VERSIONS and len(data) >= 2:
                        sh["selected_version"] = d.u16()
                    elif et == EXT_ALPN:
                        lst = _Reader(d.take(d.u16()))
                        if lst.left():
                            sh["alpn"] = lst.take(lst.u8()).decode("ascii", "replace")
                except ValueError:
                    continue
        return sh
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------
def ja3_string(ch: dict) -> str:
    ciphers = [c for c in ch["ciphers"] if not is_grease(c)]
    exts = [e for e in ch["extensions"] if not is_grease(e)]
    groups = [g for g in ch["groups"] if not is_grease(g)]
    return ",".join([
        str(ch["legacy_version"]),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in exts),
        "-".join(str(g) for g in groups),
        "-".join(str(p) for p in ch["point_formats"]),
    ])


def ja3(ch: dict) -> str:
    return hashlib.md5(ja3_string(ch).encode()).hexdigest()


def ja3s_string(sh: dict) -> str:
    exts = [e for e in sh["extensions"] if not is_grease(e)]
    return f"{sh['legacy_version']},{sh['cipher']}," + "-".join(str(e) for e in exts)


def ja3s(sh: dict) -> str:
    return hashlib.md5(ja3s_string(sh).encode()).hexdigest()


def offered_max_version(ch: dict) -> int:
    sv = [v for v in ch.get("supported_versions", []) if not is_grease(v)]
    return max(sv) if sv else ch["legacy_version"]


def _alpn_code(ch: dict) -> str:
    if not ch.get("alpn_raw"):
        return "00"
    raw = ch["alpn_raw"][0]
    if not raw:
        return "00"
    alnum = lambda c: 0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A
    if alnum(raw[0]) and alnum(raw[-1]):
        return chr(raw[0]) + chr(raw[-1])
    hx = raw.hex()
    return hx[0] + hx[-1]


def ja4_parts(ch: dict, transport: str = "t") -> dict:
    ciphers = [c for c in ch["ciphers"] if not is_grease(c)]
    exts = [e for e in ch["extensions"] if not is_grease(e)]
    version = _JA4_VERSION.get(offered_max_version(ch), "00")
    a = (f"{transport}{version}{'d' if ch.get('sni_present') else 'i'}"
         f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{_alpn_code(ch)}")
    b_raw = ",".join(sorted(f"{c:04x}" for c in ciphers))
    c_exts = sorted(f"{e:04x}" for e in exts if e not in (EXT_SNI, EXT_ALPN))
    sig = [f"{s:04x}" for s in ch.get("sig_algs", []) if not is_grease(s)]
    c_raw = ",".join(c_exts) + ("_" + ",".join(sig) if sig else "")
    b = hashlib.sha256(b_raw.encode()).hexdigest()[:12] if ciphers else "000000000000"
    c = hashlib.sha256(c_raw.encode()).hexdigest()[:12] if c_exts else "000000000000"
    return {"a": a, "b": b, "c": c, "b_raw": b_raw, "c_raw": c_raw}


def ja4(ch: dict, transport: str = "t") -> str:
    p = ja4_parts(ch, transport)
    return f"{p['a']}_{p['b']}_{p['c']}"


def client_summary(ch: dict, transport: str = "t") -> dict:
    """The fields a flow event carries for its ClientHello."""
    ver = offered_max_version(ch)
    return {
        "transport": "quic" if transport == "q" else "tcp",
        "ja3": ja3(ch),
        "ja4": ja4(ch, transport),
        "sni": ch.get("sni"),
        "alpn": ch.get("alpn", [])[:4],
        "offered_version": _VERSION_NAME.get(ver, hex(ver)),
        "cipher_count": len([c for c in ch["ciphers"] if not is_grease(c)]),
        "extension_count": len([e for e in ch["extensions"] if not is_grease(e)]),
        "ech": bool(ch.get("ech")),
    }


def server_summary(sh: dict) -> dict:
    ver = sh.get("selected_version") or sh["legacy_version"]
    return {
        "ja3s": ja3s(sh),
        "negotiated_version": _VERSION_NAME.get(ver, hex(ver)),
        "cipher": f"0x{sh['cipher']:04x}",
        "server_alpn": sh.get("alpn"),
    }
