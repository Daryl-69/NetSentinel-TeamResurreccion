"""Fast capture reader: pcap / pcapng -> the header fields the extractors need.

Scapy dissects every layer of every packet into Python objects, which costs
far more than the extractors need: they read a dozen header fields and, for
the first packets of a TLS/QUIC flow and for DNS, a few payload bytes. This
module reads capture files with ``struct`` and hands those fields straight
to FlowExtractor.process_fields / DNSExtractor.process_fields. It is used
for capture replay and the throughput benchmark; live capture still goes
through Scapy's sniffer.

It reproduces Scapy's view of each packet exactly where the extractors
depend on it (tests/test_fastpath_parity.py replays the same capture both
ways and compares every event):
  * payload_size = captured bytes after the IP header, including Ethernet
    padding, which is what len(packet[IP].payload) returns;
  * DNS is recognised on UDP/TCP port 53 and UDP 5353, as Scapy binds it;
  * non-first IPv4 fragments carry no transport header and are skipped.
Link types handled: Ethernet (with 802.1Q/802.1ad tags), raw IPv4/IPv6,
Linux cooked (SLL, SLL2) and BSD loopback. Anything else makes the caller
fall back to Scapy for that file.
"""
from __future__ import annotations

import socket
import struct
from typing import Iterator, Optional

LINKTYPES = {0, 1, 12, 14, 101, 113, 228, 229, 276}
_AF4, _AF6 = socket.AF_INET, socket.AF_INET6
_ntop = socket.inet_ntop
_u16 = struct.Struct("!H").unpack_from
_u32 = struct.Struct("!I").unpack_from
DNS_PORTS_UDP = (53, 5353)


class UnsupportedCapture(Exception):
    pass


# ---------------------------------------------------------------------------
# readers
# ---------------------------------------------------------------------------
def iter_capture(path: str) -> Iterator[tuple]:
    """Yield (ts, linktype, frame_bytes, wire_len) for every packet."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(fh)
        elif head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _iter_pcap(fh)
        else:
            raise UnsupportedCapture("not a pcap or pcapng file")


def _iter_pcap(fh) -> Iterator[tuple]:
    gh = fh.read(24)
    if len(gh) < 24:
        return
    magic = gh[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", gh[20:24])[0] & 0x0FFFFFFF
    if linktype not in LINKTYPES:
        raise UnsupportedCapture(f"link type {linktype}")
    rec = struct.Struct(endian + "IIII")
    div = 1e9 if nano else 1e6
    read = fh.read
    while True:
        h = read(16)
        if len(h) < 16:
            return
        sec, frac, incl, orig = rec.unpack(h)
        data = read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, linktype, data, orig


def _iter_pcapng(fh) -> Iterator[tuple]:
    read = fh.read
    endian = "<"
    ifaces = []          # (linktype, ts_divisor)
    while True:
        h = read(8)
        if len(h) < 8:
            return
        btype = struct.unpack(endian + "I", h[:4])[0]
        if btype == 0x0A0D0D0A:
            bom = read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", h[4:8])[0]
            read(blen - 12)
            ifaces = []
            continue
        blen = struct.unpack(endian + "I", h[4:8])[0]
        if blen < 12:
            return
        body = read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:                                  # interface description
            lt = struct.unpack(endian + "H", body[:2])[0]
            div = 1e6
            o = 8
            while o + 4 <= len(body) - 4:
                code, olen = struct.unpack(endian + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:
                    v = body[o + 4]
                    div = (2.0 ** (v & 0x7F)) if (v & 0x80) else (10.0 ** v)
                o += 4 + ((olen + 3) & ~3)
            ifaces.append((lt, div))
        elif btype == 6:                                # enhanced packet
            ifid, hi, lo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            if ifid >= len(ifaces):
                continue
            lt, div = ifaces[ifid]
            yield ((hi << 32) | lo) / div, lt, body[20:20 + cap], orig
        elif btype == 3:                                # simple packet (no timestamp)
            continue


# ---------------------------------------------------------------------------
# frame parser
# ---------------------------------------------------------------------------
class Pkt:
    """Header fields of one TCP/UDP packet (what the extractors read)."""
    __slots__ = ("ts", "src", "dst", "proto", "sport", "dport", "flags", "window",
                 "header_size", "payload_size", "l4_len", "l4_off", "buf", "wirelen", "ip6")

    def payload(self) -> bytes:
        o = self.l4_off + self.header_size
        return bytes(self.buf[o:o + self.l4_len])


def parse_frame(ts: float, linktype: int, buf: bytes, wirelen: int) -> Optional[Pkt]:
    """Parse one frame; None for anything that is not IPv4/IPv6 TCP/UDP."""
    try:
        if linktype == 1:
            o = 14
            et = _u16(buf, 12)[0]
            while et in (0x8100, 0x88A8, 0x9100):
                et = _u16(buf, o + 2)[0]
                o += 4
        elif linktype in (101, 12, 14, 228, 229):
            o = 0
            v = buf[0] >> 4
            et = 0x0800 if v == 4 else (0x86DD if v == 6 else 0)
        elif linktype == 113:
            o, et = 16, _u16(buf, 14)[0]
        elif linktype == 276:
            o, et = 20, _u16(buf, 0)[0]
        elif linktype == 0:
            fam = struct.unpack_from("<I", buf, 0)[0]
            if fam > 0xFFFF:
                fam = struct.unpack_from(">I", buf, 0)[0]
            o = 4
            et = 0x0800 if fam == 2 else (0x86DD if fam in (10, 24, 28, 30) else 0)
        else:
            return None

        if et == 0x0800:
            if len(buf) < o + 20:
                return None
            ihl = (buf[o] & 0x0F) * 4
            total = _u16(buf, o + 2)[0]
            frag = _u16(buf, o + 6)[0] & 0x1FFF
            proto = buf[o + 9]
            if frag or proto not in (6, 17):
                return None
            src, dst = _ntop(_AF4, buf[o + 12:o + 16]), _ntop(_AF4, buf[o + 16:o + 20])
            l3_payload = o + ihl
            ip_payload_len = total - ihl
            l4 = l3_payload
            ip6 = False
        elif et == 0x86DD:
            if len(buf) < o + 40:
                return None
            plen = _u16(buf, o + 4)[0]
            nh = buf[o + 6]
            src, dst = _ntop(_AF6, buf[o + 8:o + 24]), _ntop(_AF6, buf[o + 24:o + 40])
            l3_payload = o + 40
            l4 = l3_payload
            hops = 0
            while nh in (0, 43, 60, 44) and hops < 6:
                if nh == 44:                              # fragment header
                    if _u16(buf, l4 + 2)[0] & 0xFFF8:
                        return None
                    nh, l4 = buf[l4], l4 + 8
                else:
                    nh, l4 = buf[l4], l4 + (buf[l4 + 1] + 1) * 8
                hops += 1
            proto = nh
            if proto not in (6, 17):
                return None
            ip_payload_len = plen - (l4 - l3_payload)     # minus extension headers
            ip6 = True
        else:
            return None

        p = Pkt()
        p.ts, p.src, p.dst, p.proto, p.buf, p.wirelen, p.ip6 = ts, src, dst, proto, buf, wirelen, ip6
        p.payload_size = max(0, len(buf) - l3_payload)
        p.l4_off = l4
        if proto == 6:
            if len(buf) < l4 + 20:
                return None
            p.sport, p.dport = _u16(buf, l4)[0], _u16(buf, l4 + 2)[0]
            dataofs = buf[l4 + 12] >> 4
            p.header_size = dataofs * 4 if dataofs else 20
            p.flags = buf[l4 + 13]
            p.window = _u16(buf, l4 + 14)[0]
            p.l4_len = max(0, ip_payload_len - p.header_size)
        else:
            if len(buf) < l4 + 8:
                return None
            p.sport, p.dport = _u16(buf, l4)[0], _u16(buf, l4 + 2)[0]
            ulen = _u16(buf, l4 + 4)[0]
            p.header_size, p.flags, p.window = 8, 0, 0
            p.l4_len = max(0, ulen - 8) if ulen else max(0, p.payload_size - 8)
        return p
    except (IndexError, struct.error, ValueError):
        return None


def is_dns(p: Pkt) -> bool:
    if p.proto == 17:
        return p.sport in DNS_PORTS_UDP or p.dport in DNS_PORTS_UDP
    return p.sport == 53 or p.dport == 53


def _qname(msg: bytes, o: int):
    labels, jumped, end, hops = [], False, None, 0
    while o < len(msg) and hops < 64:
        n = msg[o]
        if n == 0:
            o += 1
            break
        if n & 0xC0 == 0xC0:
            if o + 1 >= len(msg):
                return None, None
            if not jumped:
                end = o + 2
            o = ((n & 0x3F) << 8) | msg[o + 1]
            jumped = True
            hops += 1
            continue
        labels.append(msg[o + 1:o + 1 + n])
        o += 1 + n
        hops += 1
    return b".".join(labels), (end if jumped else o)


def parse_dns(p: Pkt) -> Optional[dict]:
    """Header, first question and sizes of a DNS message, or None."""
    msg = p.payload()
    if p.proto == 6:
        if len(msg) < 2:
            return None
        msg = msg[2:]
    if len(msg) < 12:
        return None
    flags = _u16(msg, 2)[0]
    qd, an = _u16(msg, 4)[0], _u16(msg, 6)[0]
    out = {"qr": flags >> 15, "rcode": flags & 0x0F, "qdcount": qd, "ancount": an,
           "qname": None, "qtype": None,
           "msg_len": (p.l4_len if p.proto == 17 else max(0, p.l4_len - 2))}
    if qd:
        name, o = _qname(msg, 12)
        if name is None or o is None or o + 4 > len(msg):
            return out if out["qr"] == 1 else None
        out["qname"] = name.decode("utf-8", errors="ignore")
        out["qtype"] = _u16(msg, o)[0]
    return out
