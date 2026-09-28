"""TLS / QUIC handshake metadata and the fast capture reader.

References used (no network needed at test time):
* JA4: the worked example published with the FoxIO JA4 specification
  (t13d1516h2_8daaf6152771_e5627efa2ab1).
* JA3: a real OpenSSL ClientHello whose JA3 was computed by the Salesforce
  reference implementation (pyja3) when the fixture was made.
* QUIC: RFC 9001 Appendix A key-derivation values, and client Initial
  datagrams produced by aioquic (one- and two-datagram ClientHellos).
* Community ID: values produced by the reference `communityid` package.
"""
import json
import os
import struct

import pytest

from netsentinel.extractor import tls_parse as T
from netsentinel.extractor import quic_initial as Q
from netsentinel.pipeline.alert_schema import community_id

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "tls_quic_fixtures.json")


@pytest.fixture(scope="module")
def fx():
    with open(FIX) as fh:
        return json.load(fh)


def _ext(t, data=b""):
    return struct.pack("!HH", t, len(data)) + data


def _ja4_example_hello() -> bytes:
    ciphers = [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
               0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
    sni = b"example.com"
    sni_ext = struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni
    alpn = b"\x02h2\x08http/1.1"
    sig = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    exts = b"".join([
        _ext(0x0a0a), _ext(0x0000, sni_ext), _ext(0x0017), _ext(0xff01, b"\x00"),
        _ext(0x000a, struct.pack("!H", 8) + struct.pack("!HHHH", 0x3a3a, 0x001d, 0x0017, 0x0018)),
        _ext(0x000b, b"\x01\x00"), _ext(0x0023), _ext(0x0010, struct.pack("!H", len(alpn)) + alpn),
        _ext(0x0005, b"\x01\x00\x00\x00\x00"),
        _ext(0x000d, struct.pack("!H", 2 * len(sig)) + b"".join(struct.pack("!H", s) for s in sig)),
        _ext(0x0012), _ext(0x0033, b"\x00\x00"), _ext(0x002d, b"\x01\x01"),
        _ext(0x002b, b"\x06" + struct.pack("!HHH", 0x5a5a, 0x0304, 0x0303)),
        _ext(0x001b, b"\x02\x00\x02"), _ext(0x4469, b"\x00\x03\x02h2"), _ext(0x0015, b"\x00" * 10)])
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x20" + b"\x22" * 32 +
            struct.pack("!H", 2 * len(ciphers)) + b"".join(struct.pack("!H", c) for c in ciphers) +
            b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_ja4_matches_specification_example():
    status, body = T.extract_handshake(_ja4_example_hello(), T.HS_CLIENT_HELLO)
    assert status == "ok"
    ch = T.parse_client_hello(body)
    assert T.ja4(ch) == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    parts = T.ja4_parts(ch)
    assert parts["b_raw"] == "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"


def test_ja3_matches_reference_implementation(fx):
    hello = bytes.fromhex(fx["openssl_client_hello_hex"])
    status, body = T.extract_handshake(hello, T.HS_CLIENT_HELLO)
    ch = T.parse_client_hello(body)
    assert T.ja3_string(ch) == fx["openssl_ja3"]
    assert T.ja3(ch) == fx["openssl_ja3_digest"]
    assert ch["sni"] == fx["openssl_sni"]


def test_grease_is_ignored():
    ch = {"legacy_version": 771, "ciphers": [0x0a0a, 0x1301], "extensions": [0x1a1a, 0x0000],
          "groups": [0x2a2a, 0x001d], "point_formats": [0], "sig_algs": [], "alpn": [], "alpn_raw": [],
          "supported_versions": [0x3a3a, 0x0304], "sni_present": True}
    assert T.ja3_string(ch) == "771,4865,0,29,0"
    assert T.ja4(ch).startswith("t13d0101")


def test_hello_split_over_segments_and_records():
    rec = _ja4_example_hello()
    assert T.extract_handshake(rec[:100], 1)[0] == "need_more"
    hs = rec[5:]
    half = len(hs) // 2
    two = (b"\x16\x03\x01" + struct.pack("!H", half) + hs[:half] +
           b"\x16\x03\x01" + struct.pack("!H", len(hs) - half) + hs[half:])
    status, body = T.extract_handshake(two, 1)
    assert status == "ok" and T.ja4(T.parse_client_hello(body)) == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert T.extract_handshake(b"GET / HTTP/1.1\r\n\r\n", 1)[0] == "not_tls"


def test_server_hello_ja3s():
    body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00" + struct.pack("!H", 0xc02f) + b"\x00"
    ext = struct.pack("!HH", 0xff01, 1) + b"\x00" + struct.pack("!HH", 0x000b, 2) + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    sh = T.parse_server_hello(body)
    assert T.ja3s_string(sh) == "771,49199,65281-11"


def test_quic_initial_keys_match_rfc9001():
    key, iv, hp = Q.client_initial_keys(bytes.fromhex("8394c8f03e515708"))
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


@pytest.mark.parametrize("case", ["quic_single", "quic_multi"])
def test_quic_client_hello_from_initials(fx, case):
    asm = Q.QuicHelloAssembler()
    body = None
    for d in fx[case]["datagrams"]:
        body = asm.feed(bytes.fromhex(d)) or body
    ch = T.parse_client_hello(body)
    assert ch["sni"] == fx[case]["sni"]
    assert ch["alpn"][0] == fx[case]["alpn_first"]
    assert T.ja4(ch, "q").startswith("q13d")


def test_quic_parsing_is_off_by_default(fx):
    from netsentinel import config
    from netsentinel.extractor.flow_extractor import FlowExtractor
    assert config.QUIC_INITIAL_PARSE is False
    d = bytes.fromhex(fx["quic_single"]["datagrams"][0])
    for enabled, expect in ((False, None), (True, "quic.example.net")):
        fe = FlowExtractor(quic_initial_parse=enabled)
        fe.process_fields(1.0, "10.0.0.5", "203.0.113.9", 17, 51000, 443, 0, 0, 8, len(d) + 8,
                          len(d), lambda: d)
        fe.process_fields(1.1, "203.0.113.9", "10.0.0.5", 17, 443, 51000, 0, 0, 8, 1208, 1200,
                          lambda: b"\x00" * 1200)
        ev = fe.flush_all()[0]
        assert (ev.get("tls") or {}).get("sni") == expect


def test_community_id_matches_reference():
    assert community_id("128.232.110.120", "66.35.250.204", 34855, 80, 6) == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert community_id("66.35.250.204", "128.232.110.120", 80, 34855, "TCP") == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert community_id("192.168.1.52", "8.8.8.8", 54585, 53, 17) == "1:d/FP5EW3wiY1vCndhwleRRKHowQ="
    assert community_id("fe80::200:86ff:fe05:80da", "fe80::260:97ff:fe07:69ea", 1022, 22, 6) == \
        "1:gS2aYcRwGJWe7UratL8/84dclq4="
    assert community_id("10.0.0.1", None, 1, 2, 6) is None


def _diverse_pcap(path, fx):
    scapy_all = pytest.importorskip("scapy.all")
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, Dot1Q, wrpcap, IPv6ExtHdrHopByHop
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    hello = bytes.fromhex(fx["openssl_client_hello_hex"])
    pk, t = [], [1758000000.0]

    def add(p, dt=0.01):
        t[0] += dt
        p.time = t[0]
        pk.append(p)
    c, s = "192.168.5.10", "203.0.113.20"
    add(Ether() / IP(src=c, dst=s) / TCP(sport=50001, dport=443, flags="S"))
    add(Ether() / IP(src=s, dst=c) / TCP(sport=443, dport=50001, flags="SA"))
    add(Ether(bytes(Ether() / IP(src=c, dst=s) / TCP(sport=50001, dport=443, flags="A")) + b"\x00" * 6))
    add(Ether() / IP(src=c, dst=s) / TCP(sport=50001, dport=443, flags="A") / Raw(hello[:200]))
    add(Ether() / IP(src=c, dst=s) / TCP(sport=50001, dport=443, flags="PA") / Raw(hello[200:]))
    for _ in range(3):
        add(Ether() / IP(src=s, dst=c) / TCP(sport=443, dport=50001, flags="A") / Raw(b"\x17" * 1400))
    add(Ether() / IP(src=c, dst=s) / TCP(sport=50001, dport=443, flags="FA"))
    add(Ether() / IP(src=s, dst=c) / TCP(sport=443, dport=50001, flags="FA"))
    add(Ether(bytes(Ether() / IP(src=c, dst=s) / TCP(sport=50001, dport=443, flags="A")) + b"\x00" * 6))
    add(Ether() / IPv6(src="fd00::10", dst="2001:db8::20") / IPv6ExtHdrHopByHop() / TCP(sport=50002, dport=443, flags="S"))
    add(Ether() / IPv6(src="fd00::10", dst="2001:db8::20") / TCP(sport=50002, dport=443, flags="PA") / Raw(hello))
    add(Ether() / IPv6(src="2001:db8::20", dst="fd00::10") / TCP(sport=443, dport=50002, flags="RA"))
    for _ in range(3):
        add(Ether() / Dot1Q(vlan=10) / IP(src="10.9.0.5", dst="10.9.0.6") / UDP(sport=4000, dport=5000) / Raw(b"u" * 300))
    add(Ether() / IP(src="192.168.5.11", dst="192.168.5.1") / UDP(sport=33333, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="www.example.org")))
    add(Ether() / IP(src="192.168.5.1", dst="192.168.5.11") / UDP(sport=53, dport=33333) / DNS(id=1, qr=1, qd=DNSQR(qname="www.example.org"), an=DNSRR(rrname="www.example.org", rdata="203.0.113.5")))
    add(Ether() / IP(src="192.168.5.11", dst="192.168.5.1") / UDP(sport=33334, dport=53) / DNS(id=2, rd=1, qd=DNSQR(qname="a1b2c3.t.tunnel-sim.net", qtype=10)))
    add(Ether() / IP(src="192.168.5.1", dst="192.168.5.11") / UDP(sport=53, dport=33334) / DNS(id=2, qr=1, rcode=3, qd=DNSQR(qname="a1b2c3.t.tunnel-sim.net", qtype=10)))
    add(Ether() / IP(src="192.168.5.12", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="printer.local", qtype=12)))
    add(Ether() / IP(src="192.168.5.11", dst="192.168.5.1") / TCP(sport=40001, dport=53, flags="PA") / DNS(id=3, qd=DNSQR(qname="big.example.org", qtype=255)))
    for i in range(5):
        add(Ether() / IP(src="192.168.5.99", dst=f"10.20.0.{i + 1}") / TCP(sport=45000 + i, dport=445, flags="S"), 0.001)
    for d in fx["quic_single"]["datagrams"]:
        add(Ether() / IP(src="192.168.5.13", dst="203.0.113.9") / UDP(sport=51000, dport=443) / Raw(bytes.fromhex(d)))
    add(Ether() / IP(src="203.0.113.9", dst="192.168.5.13") / UDP(sport=443, dport=51000) / Raw(b"\xc0" * 1200))
    add(Ether() / IP(src="192.168.5.14", dst="203.0.113.30", frag=100, proto=17) / Raw(b"y" * 100))
    wrpcap(path, pk)


def test_fast_reader_matches_scapy(tmp_path, fx):
    """Replaying one capture with Scapy and with the fast reader gives the
    same events, field for field, and the same extractor counters."""
    from netsentinel.extractor.pcap_reader import PacketProcessor
    from netsentinel.pipeline.metrics import PipelineMetrics
    path = str(tmp_path / "diverse.pcap")
    _diverse_pcap(path, fx)

    def run(fast):
        pp = PacketProcessor(use_cicflowmeter=False, metrics=PipelineMetrics(), fast_reader=fast,
                             quic_initial_parse=True)
        evs = [e for e in pp.process_pcap(path) if e is not None]
        for e in evs:
            e.pop("ingest_wall", None)
        st = pp.stats
        st.pop("reader")
        return evs, st, pp.reader_used

    a, sa, ra = run(False)
    b, sb, rb = run(True)
    assert (ra, rb) == ("scapy", "fast")
    assert len(a) == len(b) and len(a) > 10
    assert a == b
    assert sa == sb
    ja4s = [e["tls"]["ja4"] for e in b if e.get("tls", {}).get("ja4")]
    assert any(j.startswith("t13") for j in ja4s) and any(j.startswith("q13") for j in ja4s)
    types = {e.get("query_type") for e in b if e["type"] == "dns"}
    assert {1, 10, 12, 255} <= types          # every query type is kept
    assert sb["flow_extractor"]["teardown_packets_absorbed"] >= 1
