"""Sensor side of Tier 2 on real traffic (netsentinel/inspector.py).

The live sensor's flow and DNS events become connection records for the
Inspector. These tests pin down who the "device" is, where hostnames come
from, and that DNS replies carry their answer addresses on both the Scapy
(live) and fast-reader (pcap import) paths.
"""
import pytest

from netsentinel.inspector import RecordBuilder


def _flow(src, dst, fwd=1000, bwd=50000, ts=1788825600.0, sni=None):
    ev = {"type": "flow", "source_ip": src, "dest_ip": dst, "timestamp": ts, "last_seen": ts + 4.0,
          "features": {"Fwd Packets Length Total": fwd, "Bwd Packets Length Total": bwd}}
    if sni:
        ev["tls"] = {"sni": sni}
    return ev


def test_outbound_flow_uses_sni_and_local_side():
    rb = RecordBuilder()
    r = rb.feed(_flow("192.168.1.10", "140.82.112.4", sni="github.com"))
    assert r == ("192.168.1.10", "140.82.112.4", "github.com", 1788825600.0, 4.0, 1000.0, 50000.0)


def test_reply_direction_flow_swaps_bytes():
    # first packet seen came from the remote side: the device is the destination
    r = RecordBuilder().feed(_flow("203.0.113.7", "192.168.1.10", fwd=40, bwd=4000))
    assert r[0] == "192.168.1.10" and r[1] == "203.0.113.7"
    assert (r[5], r[6]) == (4000.0, 40.0)


def test_transit_traffic_is_not_a_device():
    rb = RecordBuilder()
    assert rb.feed(_flow("198.51.100.1", "198.51.100.2")) is None
    assert rb.skipped == 1


def test_interface_address_makes_a_global_ip_local():
    rb = RecordBuilder(local_ips=["2401:db00::5"])
    assert rb.feed(_flow("2401:db00::5", "2607:f8b0::1"))[0] == "2401:db00::5"


def test_dns_answers_name_later_flows():
    rb = RecordBuilder()
    assert rb.feed({"type": "dns_response", "domain": "api.telegram.org",
                    "answer_ips": ["149.154.167.220"]}) is None
    r = rb.feed(_flow("10.0.0.5", "149.154.167.220"))
    assert r[2] == "api.telegram.org"


def _dns_reply_bytes():
    scapy = pytest.importorskip("scapy.all")
    pkt = (scapy.Ether() / scapy.IP(src="8.8.8.8", dst="192.168.1.10") /
           scapy.UDP(sport=53, dport=40000) /
           scapy.DNS(id=1, qr=1, qd=scapy.DNSQR(qname="example.org"),
                     an=[scapy.DNSRR(rrname="example.org", type="A", rdata="93.184.215.14"),
                         scapy.DNSRR(rrname="example.org", type="AAAA", rdata="2606:2800:21f:cb07::1")]))
    return pkt


def test_scapy_path_reports_answer_ips():
    from scapy.all import Ether
    from netsentinel.extractor.dns_extractor import DNSExtractor
    pkt = Ether(bytes(_dns_reply_bytes()))          # dissected from bytes, as the sniffer delivers it
    ev = DNSExtractor().process_packet(pkt)
    assert ev["type"] == "dns_response"
    assert ev["answer_ips"] == ["93.184.215.14", "2606:2800:21f:cb07::1"]


def test_fast_reader_reports_answer_ips():
    from netsentinel.extractor.fastpath import parse_frame, parse_dns
    raw = bytes(_dns_reply_bytes())
    p = parse_frame(0.0, 1, raw, len(raw))
    d = parse_dns(p)
    assert d["qr"] == 1
    assert d["answer_ips"] == ["93.184.215.14", "2606:2800:21f:cb07::1"]
