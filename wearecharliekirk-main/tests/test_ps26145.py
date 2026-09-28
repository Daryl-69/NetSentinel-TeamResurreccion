"""PS 26145 detectors, alert schema v1 and the honesty fixes.

Every scenario here is synthetic (netsentinel/simulator) or hand-built;
these tests show the code does what it says, not how well it detects real
attacks.
"""
import json
import math
import random
import time

import numpy as np
import pytest

from netsentinel import config
from netsentinel.detectors.base import is_internal, is_external
from netsentinel.detectors.beacon_score import BeaconScorer, features, merge, fft_prom, mad_ratio
from netsentinel.detectors.ddos_volume import DDoSWindowTracker
from netsentinel.detectors.dns_behaviour import DnsBehaviourTracker
from netsentinel.detectors.exfil_ratio import ByteRatioExfilDetector
from netsentinel.detectors.tls_sessions import EncryptedSessionDetector
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.pipeline.alert_schema import ALERT_SCHEMA, SCHEMA_ID, validate_alert
from netsentinel.pipeline.metrics import PipelineMetrics
from netsentinel.simulator import traffic_gen as G


# ------------------------------------------------------------------ fixtures
@pytest.fixture(scope="module")
def registry():
    from netsentinel.models.registry import ModelRegistry
    reg = ModelRegistry()
    reg.load_all()
    if reg.dga is None or reg.ddos is None:
        pytest.skip("model files not available")
    return reg


@pytest.fixture
def analyzer(registry):
    from netsentinel.pipeline.analyzer import FlowAnalyzer
    m = PipelineMetrics()
    return FlowAnalyzer(registry, AlertManager(max_stored=10000, metrics=m), metrics=m)


def run(an, events):
    out = []
    for e in events if isinstance(events, list) else [events]:
        out += an.analyze(e)
    return out


def schema_check(alert):
    """Full JSON Schema validation when jsonschema >= 4.0 is installed (older
    releases have no draft 2020-12 validator); the sensor's own structural
    check always."""
    assert validate_alert(alert) == []
    try:
        import jsonschema
    except ImportError:
        return
    validator = getattr(jsonschema, "Draft202012Validator", None)
    if validator is None:
        return
    validator(ALERT_SCHEMA).validate(alert)


# ------------------------------------------------------------ alert schema
def test_alert_schema_v1_and_no_invented_fields():
    am = AlertManager()
    a = am.create_alert({"threat": "DGA", "confidence": 0.91, "model": "dga_cnn_bilstm_v2", "entropy": 4.2},
                        source_ip="192.168.1.9", dest_ip=None,
                        flow_meta={"scope": "dns_query", "src_ip": "192.168.1.9", "dst_ip": None, "domain": "x.example"},
                        context={"event_start": 1758000000.0, "t0_perf": time.perf_counter(), "ingest_wall": time.time()})
    schema_check(a)
    assert a["schema"] == SCHEMA_ID
    assert a["dest_ip"] is None                     # no placeholder destination
    assert "geo" not in a                           # no invented location
    assert a["ps_category"] == "c"
    assert a["event_time"].startswith("2025-09-16")
    assert a["latency_ms"]["pipeline"] >= 0 and a["latency_ms"]["ingest_to_alert"] >= 0
    f = am.create_alert({"threat": "DDoS", "confidence": 0.99, "model": "ddos_binary_xgboost"},
                        flow_meta={"scope": "flow", "src_ip": "203.0.113.4", "src_port": 4444,
                                   "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": 6})
    schema_check(f)
    assert f["flow_id"]["community_id"].startswith("1:")
    assert am.schema_violations == 0


def test_schema_file_matches_code():
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "alert_schema_v1.json")
    if not os.path.exists(path):
        pytest.skip("docs/alert_schema_v1.json not present")
    with open(path) as fh:
        assert json.load(fh) == json.loads(json.dumps(ALERT_SCHEMA))


def test_exfil_alert_never_invents_byte_counts(analyzer):
    ev = {"type": "dns", "domain": "6281e67dca45574f.f309ead35609407c.6bf.tunnel-data.info",
          "source_ip": "192.168.1.50", "dest_ip": "192.168.1.1", "timestamp": time.time(), "query_type": 1}
    alerts = run(analyzer, ev)
    exfil = [a for a in alerts if a["threat_class"] == "Data Exfiltration"]
    assert exfil, "the VAE should flag this tunnel-shaped name"
    assert "byte_ratio" not in exfil[0]["evidence"]   # nothing measured -> nothing reported
    for a in alerts:
        schema_check(a)


# ------------------------------------------------------------------- DDoS
def test_syn_flood_and_reflection_families():
    t = DDoSWindowTracker(config.DDOS_VOLUME)
    fired = []
    for e in G.generate_syn_flood_burst(400) + G.generate_reflection_burst(400):
        t.observe(e)
        r = t.evaluate(e["dest_ip"], e["timestamp"])
        if r:
            fired.append(r)
    fams = {r["subtype"] for r in fired}
    assert "SYN flood (spoofed sources likely)" in fams
    assert "UDP reflection/amplification (NTP)" in fams
    syn = next(r for r in fired if r["subtype"].startswith("SYN"))
    assert syn["src_ip_entropy_norm"] > 0.95 and syn["distinct_sources"] >= 100
    assert t.replay(syn["_replay_inputs"])["confidence"] == syn["confidence"]


def test_one_client_lookup_burst_is_not_a_ddos():
    """Found on the team's own traffic: one host sent 205 DNS queries (each
    from a new source port) to its resolver within a second. Rate and shape
    match a UDP flood; with one source it is not a distributed attack."""
    t = DDoSWindowTracker(config.DDOS_VOLUME)
    base = 1758000000.0
    burst = [G._probe_flow("192.168.1.30", "203.0.113.53", 40000 + i, 53, 17, base + i / 250.0,
                           pkts=2, size=40, syn=False) for i in range(250)]
    fired = [r for e in burst if (t.observe(e) or True) and (r := t.evaluate(e["dest_ip"], e["timestamp"]))]
    assert fired == []
    s = t.summary("203.0.113.53")
    assert s["family"] == "UDP flood" and s["distinct_sources"] == 1 and s["flow_rate_per_s"] >= 100


def test_scan_is_not_called_a_flood(analyzer):
    alerts = run(analyzer, G.generate_port_scan_burst())
    assert not [a for a in alerts if a["threat_class"] == "DDoS"]
    alerts = analyzer.tick(time.time() + 120)
    assert [a for a in alerts if a["threat_class"] == "Port Scan"]


def test_xgboost_ddos_needs_a_filled_window_and_names_the_family(analyzer):
    alerts = run(analyzer, [G.generate_ddos_flow() for _ in range(40)])
    ddos = [a for a in alerts if a["threat_class"] == "DDoS"]
    assert len(ddos) == 1                           # one alert, repeats held by the cooldown
    assert ddos[0]["threat_subtype"].startswith("SYN flood")
    assert ddos[0]["evidence"]["flows_in_window"] >= 20
    assert "attack_type" not in ddos[0]["evidence"]  # the old mislabel ("Benign") is gone


# -------------------------------------------------------------------- DNS
def test_dns_record_type_and_nxdomain_rules():
    d = DnsBehaviourTracker(config.DNS_BEHAVIOUR)
    out = []
    for e in G.generate_txt_tunnel(40) + G.generate_nxdomain_burst(32):
        out += d.observe_query(e) if e["type"] == "dns" else d.observe_response(e)
    rules = {r["rule"] for r in out}
    assert rules == {"record_type_anomaly", "nxdomain_burst"}
    for r in out:
        assert d.replay(r["_replay_inputs"])["confidence"] == r["confidence"]


def test_dns_model_alert_repeats_are_held(registry):
    """One DGA/tunnel model alert per (source, base domain) per
    DNS_MODEL_ALERT_REPEAT_S; the queries in between are counted, not
    alerted (on real traffic one name used to raise an alert a minute)."""
    from netsentinel.pipeline.analyzer import FlowAnalyzer
    is_dga = lambda a: str(a.get("detector", "")).startswith("dga_cnn")
    probe = FlowAnalyzer(registry, AlertManager(max_stored=1000))
    random.seed(5)
    flagged = None
    for _ in range(300):
        e = G.generate_dga_dns()
        if [a for a in run(probe, e) if is_dga(a)]:
            flagged = e
            break
    assert flagged is not None
    an = FlowAnalyzer(registry, AlertManager(max_stored=1000))
    t0, got = 1758000000.0, []
    for i in range(30):                         # the same name every 40 s for 20 min
        got += [a for a in run(an, dict(flagged, timestamp=t0 + 40 * i)) if is_dga(a)]
    assert config.DNS_MODEL_ALERT_REPEAT_S == 600
    assert len(got) == 2
    assert got[1]["evidence"]["alerts_suppressed_since_last"] == 15
    assert got[1]["evidence"]["query_count"] == 17


def test_dns_rules_quiet_on_normal_lookups():
    d = DnsBehaviourTracker(config.DNS_BEHAVIOUR)
    out = []
    for _ in range(600):
        e = G.generate_normal_dns()
        e["source_ip"] = "192.168.1.10"
        out += d.observe_query(e)
        out += d.observe_response({"type": "dns_response", "domain": e["domain"], "source_ip": e["source_ip"],
                                   "rcode": 0, "response_bytes": 120, "timestamp": e["timestamp"]})
    assert out == []


def test_every_query_type_is_kept():
    from netsentinel.extractor.dns_extractor import DNSExtractor
    x = DNSExtractor()
    for qt in (1, 10, 16, 255, 65280, 12):
        ev = x.process_fields(1.0, "192.168.1.2", "192.168.1.1", 0, "abc.example.net", qt, 0, 0, 40)
        assert ev and ev["query_type"] == qt
    assert x.process_fields(1.0, "192.168.1.2", "192.168.1.1", 0, "1.0.168.192.in-addr.arpa", 12, 0, 0, 40)["lexical"] is False


# --------------------------------------------------------------- C2 beacon
def _offline(conns, n_src, cap_hours, W):
    """model_comparisons/c2_beacon_score.py, verbatim formulas."""
    def fft_prom_o(iats):
        iats = np.asarray(iats, dtype=np.float64)
        if len(iats) < 4: return 0.0
        m = np.abs(np.fft.rfft(iats))[1:]
        if len(m) == 0 or m.sum() == 0: return 0.0
        return float((m.max() - np.median(m)) / (np.std(m) + 1e-9))

    def mad_o(x):
        x = np.asarray(x, dtype=np.float64); med = np.median(x)
        return 1.0 if med <= 0 else float(np.median(np.abs(x - med)) / med)
    t = np.array([m[0] for m in conns]); b = np.array([m[1] for m in conns]); iat = np.diff(t)
    T = 1 - min(1.0, mad_o(iat)); P = fft_prom_o(iat); F = min(1.0, P / 8.0)
    S = 1 - min(1.0, mad_o(b)); R = 1.0 / max(n_src, 1)
    hrs = {int(x // 3600) for x in t}; C = min(1.0, len(hrs) / max(len(cap_hours), 1))
    return W["T"] * T + W["F"] * F + W["S"] * S + W["R"] * R + W["C"] * C


def test_live_score_uses_the_offline_formula():
    rnd = random.Random(3)
    conns = [[1758000000.0 + i * 61 * (1 + rnd.uniform(-0.05, 0.05)), 900 + rnd.randint(-20, 20)] for i in range(60)]
    W = config.C2_COMBINED["weights"]
    live = features(merge(conns), 2, {1, 2, 3}, W)["score"]
    assert math.isclose(live, _offline(merge(conns), 2, {1, 2, 3}, W), rel_tol=1e-12)


def test_c2_beacon_alerts_and_noise_does_not():
    s = BeaconScorer(config.C2_COMBINED)
    fired = [r for e in G.generate_c2_beacon() if (r := s.observe(e))]
    assert len(fired) == 1 and fired[0]["score"] >= 0.80
    assert s.replay(fired[0]["_replay_inputs"])["confidence"] == fired[0]["confidence"]
    s2 = BeaconScorer(config.C2_COMBINED)
    rnd = random.Random(1)
    t = 1758000000.0
    for _ in range(80):                            # Poisson check-ins, random sizes
        t += rnd.expovariate(1 / 60.0) + 6
        e = G.generate_normal_flow()
        e.update(source_ip="192.168.1.5", dest_ip="203.0.113.9", dest_port=443, timestamp=t)
        e["features"]["Fwd Packets Length Total"] = rnd.uniform(200, 20000)
        assert s2.observe(e) is None
    ntp = G.generate_c2_beacon()
    s3 = BeaconScorer(config.C2_COMBINED)
    for e in ntp:
        e["dest_port"] = 123
        assert s3.observe(e) is None               # known periodic service


# -------------------------------------------------------------- TLS / JA4
def test_tls_implant_alerts_browsers_do_not():
    d = EncryptedSessionDetector(config.TLS_SESSIONS, None)
    quiet = []
    for _ in range(300):
        e = G.generate_normal_flow()
        if e.get("tls"):
            quiet.append(d.observe(e))
    assert not any(quiet)
    fired = [r for e in G.generate_tls_implant() if (r := d.observe(e))]
    assert len(fired) == 1
    r = fired[0]
    assert r["clients_with_fingerprint"] == 1 and "no SNI" in r["hello_flags"]
    assert d.replay(r["_replay_inputs"])["confidence"] == r["confidence"]


def test_tls_blocklist_fires_on_first_session(tmp_path):
    implant = G.generate_tls_implant(sessions=1)[0]
    bl = tmp_path / "bl.json"
    bl.write_text(json.dumps({"ja4": {implant["tls"]["ja4"]: "test entry"}}))
    d = EncryptedSessionDetector(config.TLS_SESSIONS, str(bl))
    r = d.observe(implant)
    assert r and r["blocklist"]["label"] == "test entry" and r["confidence"] == 0.99


def test_shipped_blocklist_is_empty():
    from netsentinel.detectors.tls_sessions import load_blocklist
    assert sum(len(v) for v in load_blocklist(config.TLS_BLOCKLIST_PATH).values()) == 0


# ------------------------------------------------------------ recon / exfil
def test_host_sweep_backstop():
    from netsentinel.pipeline.portscan_integration import PortScanRouter
    r = PortScanRouter(network_info_path=config.portscan.network_info_path, cfg=config)
    recs = []
    for e in G.generate_host_sweep(hosts=40):
        rec = dict(e["features"], **{"Src IP": e["source_ip"], "Dst IP": e["dest_ip"], "Dst Port": e["dest_port"],
                                     "Src Port": e["source_port"], "Timestamp": 1758000005.0})
        recs.append(rec)
    alerts = r.handle_batch(recs)
    assert alerts and alerts[0]["evidence"]["sweep_hosts"] == 40 and alerts[0]["scan_type"] == "horizontal"
    # a client reaching 60 web servers is browsing, not a sweep
    web = [{"Src IP": "192.168.1.7", "Dst IP": f"203.0.113.{i}", "Dst Port": 443, "Src Port": 50000 + i,
            "Timestamp": 1758000005.0, "Protocol": 6, "Total Fwd Packets": 10, "Total Backward Packets": 10}
           for i in range(60)]
    assert all(a["evidence"]["sweep_hosts"] < 32 for a in r.handle_batch(web))


def test_service_discovery_is_not_a_scan(analyzer):
    """mDNS / SSDP / LLMNR / DHCP discovery goes to group addresses that never
    answer. Found on the team's own traffic: every such flow looked like an
    unanswered probe of a missing host, and the scan model flagged the
    senders. Group destinations are now left out of the scan window."""
    from netsentinel.detectors.base import is_group_destination
    from netsentinel.extractor.flow_extractor import FlowExtractor
    assert is_group_destination("224.0.0.251") and is_group_destination("ff02::fb")
    assert is_group_destination("255.255.255.255") and not is_group_destination("192.168.1.255")
    assert not is_group_destination("10.0.0.3") and not is_group_destination(None)
    fe = FlowExtractor(probe_timeout=5.0)
    groups = [("224.0.0.251", 5353), ("239.255.255.250", 1900), ("224.0.0.252", 5355),
              ("ff02::fb", 5353), ("ff02::c", 1900), ("ff02::1:3", 5355), ("255.255.255.255", 67)]
    hosts = ["192.168.1.20", "192.168.1.21", "fe80::1c2b:3aff:fe4d:1"]
    t0 = t = 1758000000.0
    events = []
    for minute in range(4):
        for k in range(12):
            for h in hosts:
                for g, port in groups:
                    if (":" in g) != (":" in h):
                        continue
                    sport = port if port == 5353 else 50000 + (k * 7 + minute) % 1000
                    fe.process_fields(t, h, g, 17, sport, port, 0, 0, 8, 60, 68)
                    t += 0.05
            t = t0 + minute * 60 + (k + 1) * 5
            events += fe.flush_expired(t)
    events += fe.flush_expired(t + 400)
    for e in events:
        e["extractor"] = "custom"
    alerts = run(analyzer, sorted(events, key=lambda e: e["timestamp"])) + analyzer.finish()
    assert not [a for a in alerts if a["threat_class"] == "Port Scan"]
    assert analyzer.portscan_rule.skipped_group == len(events)
    # a real vertical scan of one internal host still fires
    scan = [dict(e, extractor="custom") for e in G.generate_port_scan_burst()]
    fired = run(analyzer, scan) + analyzer.finish()
    assert [a for a in fired if a["threat_class"] == "Port Scan"]


def test_browsing_burst_is_not_a_scan(analyzer):
    """60 answered HTTPS connections from one client to 60 servers in a
    minute. The tree reads flows as one-way records (like its NetFlow
    training data), so without the exemption this is 60 'unanswered'
    targets and a CRITICAL host sweep."""
    t0 = 1758000000.0
    burst = []
    for i in range(60):
        e = G._probe_flow("192.168.1.7", f"203.0.113.{i + 10}", 50000 + i, 443, 6, t0 + i * 0.5,
                          pkts=12, size=600, syn=True, bwd_pkts=14, bwd_size=9000)
        e["features"]["ACK Flag Count"] = 1
        e["extractor"] = "custom"
        burst.append(e)
    alerts = run(analyzer, burst) + analyzer.finish()
    assert not [a for a in alerts if a["threat_class"] == "Port Scan"]
    assert analyzer.portscan_rule.skipped_external_service == 60
    # the same fan-out toward internal hosts on a service port is still a sweep
    sweep = [dict(e, extractor="custom") for e in G.generate_host_sweep(hosts=60)]
    fired = run(analyzer, sweep) + analyzer.finish()
    assert [a for a in fired if a["threat_class"] == "Port Scan"]


def test_succession_is_capped_below_the_trees_artifact_splits():
    """The tree's succession splits (2,334.5 / 2,979.5 windows) rest on 6 of
    12,911 training events; uncapped, any host active that long is flagged
    every minute afterwards."""
    from netsentinel.extractor.network_event_builder import Flow, NetworkEventBuilder, SUCCESSION_CAP
    from netsentinel.models.portscan_detector import SPSDDetector
    from netsentinel.netinfo.network_info import load_network_info
    b = NetworkEventBuilder(load_network_info(config.portscan.network_info_path))
    ev = None
    for w in range(3100):                       # one answered connection a minute for 52 hours
        rec = {"Src IP": "192.168.1.7", "Dst IP": "203.0.113.9", "Src Port": 50000, "Dst Port": 8883,
               "Protocol": 6, "Timestamp": 1758000000.0 + 60 * w,
               "Total Fwd Packets": 10, "Total Backward Packets": 10}   # the analyzer's record shape
        ev = b.build([Flow.from_cic_record(rec)])[0]
    assert ev.rwa_count == 1                    # read as a one-way record: the reply is not seen
    assert ev.succession_count == SUCCESSION_CAP == 2333
    spsd = SPSDDetector(config.portscan.model_path)
    if spsd.is_available:
        assert spsd.predict(ev)[0] is False


def test_split_window_counts_once():
    """The analyzer flushes the scan buffer every 1,000 flows, so one window
    can reach the builder in several batches: succession must advance once
    per window, and the analyzer raises one alert per source and window."""
    from netsentinel.extractor.network_event_builder import Flow, NetworkEventBuilder
    from netsentinel.netinfo.network_info import load_network_info
    b = NetworkEventBuilder(load_network_info(config.portscan.network_info_path))
    t = 1758000000.0
    for w in range(3):
        for part in range(4):                   # four batches of the same window
            ev = b.build([Flow("192.168.1.7", "203.0.113.9", 50000 + part, 8883, "TCP",
                               t + 60 * w + part)])[0]
            assert ev.succession_count == w + 1


def test_byte_ratio_exfil():
    d = ByteRatioExfilDetector(config.EXFIL_RATIO)
    fired = [r for e in G.generate_exfil_upload() if (r := d.observe(e))]
    assert len(fired) == 1 and fired[0]["out_in_ratio"] >= 10
    down = ByteRatioExfilDetector(config.EXFIL_RATIO)
    for e in G.generate_exfil_upload():               # reverse the direction: a download
        f = e["features"]
        f["Fwd Packets Length Total"], f["Bwd Packets Length Total"] = f["Bwd Packets Length Total"], f["Fwd Packets Length Total"]
        assert down.observe(e) is None
    oneway = ByteRatioExfilDetector(config.EXFIL_RATIO)
    for e in G.generate_exfil_upload():
        e["features"]["Total Backward Packets"] = 0     # sensor saw one direction only
        assert oneway.observe(e) is None
    assert oneway.skipped_one_way == 3


def test_address_scopes():
    assert is_internal("10.2.3.4") and is_internal("fd00::1") and not is_internal("8.8.8.8")
    assert is_external("203.0.113.9") and not is_external("192.168.1.1") and not is_external("224.0.0.1")


# ------------------------------------------------------- extractor behaviour
def test_probe_stub_and_teardown_absorption():
    from netsentinel.extractor.flow_extractor import FlowExtractor, FLAG_SYN, FLAG_ACK, FLAG_FIN
    fe = FlowExtractor(probe_timeout=5.0)
    fe.process_fields(100.0, "192.168.1.9", "10.0.0.7", 6, 40000, 445, FLAG_SYN, 1024, 20, 20, 0)
    stubs = fe.flush_expired(106.0)
    assert len(stubs) == 1 and stubs[0]["stub"] and stubs[0]["features"]["SYN Flag Count"] == 1
    fe = FlowExtractor()
    a, b = ("192.168.1.9", 40001), ("203.0.113.5", 443)
    fe.process_fields(1.0, a[0], b[0], 6, a[1], b[1], FLAG_SYN, 1024, 20, 20, 0)
    fe.process_fields(1.1, b[0], a[0], 6, b[1], a[1], FLAG_SYN | FLAG_ACK, 1024, 20, 20, 0)
    done = fe.process_fields(1.2, a[0], b[0], 6, a[1], b[1], FLAG_FIN | FLAG_ACK, 1024, 20, 20, 0)
    assert done and done["type"] == "flow"
    assert fe.process_fields(1.3, b[0], a[0], 6, b[1], a[1], FLAG_FIN | FLAG_ACK, 1024, 20, 20, 0) is None
    assert fe.process_fields(1.4, a[0], b[0], 6, a[1], b[1], FLAG_ACK, 1024, 20, 20, 0) is None
    assert fe.flush_all() == [] and fe.stats["teardown_packets_absorbed"] == 2


# ------------------------------------------------------------ integrity/replay
def test_rule_alert_replay_passes_and_catches_tampering():
    from netsentinel.integrity.replay import ReplayEngine
    from netsentinel.integrity.encoding import confidence_to_ppm

    class Reg:
        pass
    s = BeaconScorer(config.C2_COMBINED)
    r = [x for e in G.generate_c2_beacon() if (x := s.observe(e))][0]
    reg = Reg()
    reg.rule_detectors = {"c2_combined": s}
    eng = ReplayEngine(reg)
    blob = {"rule_key": "c2_combined", "names": ["rule_inputs"],
            "values": [json.dumps(r["_replay_inputs"], sort_keys=True, separators=(",", ":"))]}
    ppm = confidence_to_ppm(r["confidence"])
    assert eng.replay("x", blob, "C2 Beacon", ppm, s.digest).status == "PASS"
    bad = json.loads(blob["values"][0])
    bad["checkins"] = [[t * 1.0 + (i % 3) * 7, b] for i, (t, b) in enumerate(bad["checkins"])]
    assert eng.replay("x", dict(blob, values=[json.dumps(bad)]), "C2 Beacon", ppm, s.digest).status == "FAIL"
    assert eng.replay("x", blob, "C2 Beacon", ppm, "sha256:0").status == "FAIL"


# ----------------------------------------------------------------- metrics
def test_metrics_rates_and_percentiles():
    m = PipelineMetrics(window_s=10)
    for i in range(100):
        m.latency("event.flow", float(i))
        m.event("flow")
        m.packet(1500)
    snap = m.snapshot()
    ev = snap["latency_ms"]["event"]["flow"]
    assert ev["n"] == 100 and ev["p50"] == pytest.approx(49.5) and ev["max"] == 99.0
    assert snap["totals"]["flows"] == 100 and snap["totals"]["bytes"] == 150000
    assert len(snap["series"]) == m.history_s


def test_all_six_families_fire_in_simulation(analyzer):
    background = [G.generate_normal_flow() for _ in range(200)]      # gives the TLS detector a population
    events = (background + G.generate_syn_flood_burst() + G.generate_c2_beacon() + G.generate_nxdomain_burst()
              + G.generate_tls_implant() + G.generate_host_sweep() + G.generate_exfil_upload())
    alerts = run(analyzer, events) + analyzer.tick(time.time() + 120)
    fams = {a["ps_category"] for a in alerts}
    assert {"a", "b", "c", "d", "e", "f"} <= fams
    for a in alerts:
        schema_check(a)
    assert analyzer.alert_manager.schema_violations == 0
