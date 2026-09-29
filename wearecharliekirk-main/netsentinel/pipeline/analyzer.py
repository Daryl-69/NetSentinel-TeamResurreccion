"""Flow Analyzer — routes every event to the detectors that read it.

The central orchestrator. It receives events from the extraction layer
(pcap replay or live capture) or from the synthetic simulator and routes
them to the models and detectors that cover PS 26145's six threat families:

  (a) DDoS            XGBoost on flow features (CIC-DDoS2019) + per-destination
                      rate / source-IP entropy / attack-family window
  (b) C2 beaconing    combined periodicity score (primary, live) with the
                      BiLSTM+FFT model's verdict attached as evidence
  (c) DGA / tunnel    CNN-BiLSTM (names), VAE (tunnel names), and the DNS
                      behaviour rules (NXDOMAIN rate, record types, fan-out)
  (d) encrypted C2    JA3/JA3S/JA4 + session size/timing profile
  (e) recon           network-event port-scan tree (SPSD) + fan-out and
                      host-sweep backstops
  (f) exfiltration    VAE on DNS names + out/in byte ratio of outbound flows

Every alert is built by AlertManager in the v1 schema, timed (analyzer time
and ingest-to-alert time go into the alert and the metrics), and sealed by
the integrity layer when it is enabled.

Event types: "flow" (stub=True for single-packet flows), "dns",
"dns_response", "session".
"""
import json
import math
import time
from collections import Counter, defaultdict

from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.config import THRESHOLDS, ETT_ALERT_ON_VPN
from netsentinel.extractor.unsw_feature_builder import (
    build_unsw_features,
    ConnectionTracker,
)
from netsentinel.extractor.dns_feature_builder import build_dns_features
from netsentinel.pipeline.portscan_integration import PortScanRouter, PortScanRule
from netsentinel.pipeline.metrics import METRICS, Timer
from netsentinel.detectors.base import Cooldown, is_group_destination, is_internal
from netsentinel.detectors.beacon_score import BeaconScorer
from netsentinel.detectors.ddos_volume import DDoSWindowTracker, flow_family, MIN_FLOWS_FOR_FAMILY
from netsentinel.detectors.dns_behaviour import DnsBehaviourTracker
from netsentinel.detectors.exfil_ratio import ByteRatioExfilDetector
from netsentinel.detectors.tls_sessions import EncryptedSessionDetector
import netsentinel.config as config

# Known-good second-level domains whose random-looking subdomains made the
# name models fire (e.g. r20swj13mr.microsoft.com). Also exempt from the DNS
# fan-out rule.
_DGA_WHITELIST_SLDS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "msedge.net", "msn.com", "live.com", "office.com", "office365.com",
    "outlook.com", "skype.com", "bing.com", "azure.com", "azureedge.net",
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "googleusercontent.com", "youtube.com", "ytimg.com", "gmail.com",
    "amazon.com", "amazonaws.com", "cloudfront.net", "aws.amazon.com",
    "apple.com", "icloud.com", "akamai.net", "akamaiedge.net",
    "cloudflare.com", "cloudflare-dns.com", "fastly.net",
    "fbcdn.net", "facebook.com", "whatsapp.net", "instagram.com",
    "github.com", "githubusercontent.com", "github.io",
    "verisign.com", "digicert.com", "letsencrypt.org",
    "w3.org", "wikipedia.org", "mozilla.org", "mozilla.net", "mozilla.com",
    "ubuntu.com", "debian.org", "centos.org",
    "update.microsoft.com",
    # package registries hit by `pip install` / `npm install` (registry.npmjs.org scores 0.77)
    "npmjs.org", "pypi.org", "pythonhosted.org",
}


class FlowAnalyzer:
    """Routes events to models and detectors and collects alerts."""

    def __init__(self, registry: ModelRegistry, alert_manager: AlertManager,
                 integrity_services: dict | None = None, metrics=None):
        self.registry = registry
        self.alert_manager = alert_manager
        self.flows_processed = 0
        # application-class telemetry from the ETT (not alerts)
        self.ett_classifications: dict[str, int] = {}
        self.metrics = METRICS if metrics is None else metrics
        if getattr(alert_manager, "metrics", None) is None:
            alert_manager.metrics = self.metrics

        # Integrity layer (None = disabled, degrades gracefully)
        self._integrity = integrity_services

        # Connection tracker for UNSW-NB15 ct_* features (port scan)
        self._conn_tracker = ConnectionTracker()

        # Port scan evidence: track recent dst ports per source IP
        self._recent_dst_ports: dict[str, set[int]] = defaultdict(set)

        # DNS alert deduplication: suppress repeated alerts for same base domain
        self._dns_alert_times: dict[str, float] = {}  # dedup_key → last alert timestamp
        self._dns_query_counts: dict[str, int] = {}   # dedup_key → total query count
        self._dns_held: dict[str, int] = {}           # dedup_key → flagged since last alert

        # Port scan router: network-event aggregation detector (process-lifetime instance)
        self.portscan_router = PortScanRouter(
            network_info_path=config.portscan.network_info_path,
            cfg=config,
        )
        self.portscan_rule = PortScanRule(self.portscan_router)
        self._cic_flow_buffer: list[dict] = []
        self._last_flush_time = 0.0
        self._portscan_alerted: dict = {}               # (src, window) already alerted

        # PS 26145 detectors
        self.ddos_tracker = DDoSWindowTracker(config.DDOS_VOLUME)
        self.ddos_cooldown = Cooldown(config.DDOS_VOLUME["cooldown_s"])
        self.dns_tracker = DnsBehaviourTracker(config.DNS_BEHAVIOUR, allow_bases=_DGA_WHITELIST_SLDS)
        self.beacon = BeaconScorer(config.C2_COMBINED)
        self.tls_detector = EncryptedSessionDetector(config.TLS_SESSIONS, config.TLS_BLOCKLIST_PATH)
        self.exfil_ratio = ByteRatioExfilDetector(config.EXFIL_RATIO)
        self.rules = {d.key: d for d in (self.ddos_tracker, self.dns_tracker, self.beacon,
                                         self.tls_detector, self.exfil_ratio, self.portscan_rule)}
        if hasattr(registry, "register_rules"):
            registry.register_rules(self.rules)

        self.bilstm_by_pair: dict[tuple, dict] = {}
        self._ddos_victims: dict[str, tuple] = {}      # destination -> (last DDoS decision, its sources)
        self.xgb_counts = {"flows_scored": 0, "flagged": 0}
        self.ett_counts = {"flows": 0, "classified": 0, "skipped_load": 0}
        from collections import OrderedDict
        self._name_cache: "OrderedDict[str, tuple]" = OrderedDict()
        self.name_cache_stats = {"hits": 0, "misses": 0}
        self._ett_tokens = float(getattr(config, "ETT_MAX_PER_SECOND", 0) or 0)
        self._ett_last = time.monotonic()
        self._raised: list[dict] = []
        self._ctx: dict = {}
        self._last_wire_ts = None

    # ==================================================================
    # Entry points
    # ==================================================================
    def analyze(self, event: dict) -> list[dict]:
        """Run one event through every detector that reads it.

        Returns every alert raised (a flush of the port-scan window can raise
        several at once). Call ``tick()`` periodically in live mode and
        ``finish()`` at the end of a replay.
        """
        self._raised = []
        # PacketProcessor.process_pcap() yields None every 1000 packets as a
        # cooperative-yield signal. Guard before counting.
        if not event:
            return []
        t0 = time.perf_counter()
        et = event.get("type", "flow")
        kind = "stub" if event.get("stub") else et
        self.flows_processed += 1
        self.metrics.event(kind)
        self._ctx = {"t0_perf": t0, "ingest_wall": event.get("ingest_wall")}
        ts = event.get("timestamp")
        if ts is not None:
            try:
                ts = float(ts)
                self._last_wire_ts = ts if self._last_wire_ts is None else max(self._last_wire_ts, ts)
            except (TypeError, ValueError):
                pass
        try:
            if et == "dns":
                self._analyze_dns(event)
            elif et == "dns_response":
                self._analyze_dns_response(event)
            elif et == "session":
                self._analyze_session(event)
            elif et == "flow":
                self._analyze_flow(event)
        finally:
            self.metrics.latency("event." + kind, (time.perf_counter() - t0) * 1000.0)
        return list(self._raised)

    def analyze_flow(self, event: dict) -> dict | None:
        """Backward-compatible single-alert entry point: the first (most
        specific) alert this event raised, or None. New callers should use
        analyze(), which returns all of them."""
        alerts = self.analyze(event)
        return alerts[0] if alerts else None

    def tick(self, now_wire: float | None = None) -> list[dict]:
        """Time-driven work for quiet periods: close a port-scan window whose
        60 s have passed even if no further flow arrives to trigger it."""
        self._raised = []
        self._ctx = {"t0_perf": time.perf_counter(), "ingest_wall": None}
        now = now_wire if now_wire is not None else self._last_wire_ts
        if (self._cic_flow_buffer and now is not None and self._last_flush_time
                and now - self._last_flush_time >= 60.0):
            self._flush_portscan(now, current_source=None)
        return list(self._raised)

    def finish(self) -> list[dict]:
        """End of a replay: evaluate whatever is still buffered."""
        self._raised = []
        self._ctx = {"t0_perf": time.perf_counter(), "ingest_wall": None}
        if self._cic_flow_buffer:
            self._flush_portscan(self._last_wire_ts or 0.0, current_source=None)
        return list(self._raised)

    # ==================================================================
    # Alert creation helpers
    # ==================================================================
    def _raise_model(self, result, seal_key, seal_input, source_ip, dest_ip, flow_meta,
                     ev_start, ev_end, extra_ctx=None):
        ctx = dict(self._ctx)
        ctx.update(event_start=ev_start, event_end=ev_end)
        if extra_ctx:
            ctx.update(extra_ctx)
        alert = self.alert_manager.create_alert(
            result, source_ip=source_ip, dest_ip=dest_ip, flow_meta=flow_meta, context=ctx)
        if alert:
            self._seal_alert(alert, seal_key, seal_input)
            self._raised.append(alert)
        return alert

    def _raise_rule(self, detector, result: dict, source_ip, dest_ip, flow_meta):
        result = dict(result)
        ev_start = result.pop("_event_start", None)
        ev_end = result.pop("_event_end", None)
        inputs = result.pop("_replay_inputs", None)
        ctx = dict(self._ctx)
        ctx.update(event_start=ev_start, event_end=ev_end,
                   confidence_kind=result.get("confidence_kind", detector.confidence_kind),
                   detector=result.get("model", detector.name))
        alert = self.alert_manager.create_alert(
            result, source_ip=source_ip, dest_ip=dest_ip, flow_meta=flow_meta, context=ctx)
        if alert:
            self._seal_rule(alert, detector, inputs)
            self._raised.append(alert)
        return alert

    def _build_flow_meta(self, event: dict) -> dict:
        """5-tuple flow_meta from event fields (top level or features)."""
        features = event.get("features", {}) or {}
        return {
            "scope": "flow",
            "src_ip":   event.get("source_ip"),
            "src_port": event.get("source_port", features.get("src_port", 0)),
            "dst_ip":   event.get("dest_ip"),
            "dst_port": event.get("dest_port", features.get("dst_port", 0)),
            "protocol": _proto_name(event.get("protocol", features.get("Protocol", 6))),
        }

    # ==================================================================
    # DNS path
    # ==================================================================
    def _analyze_dns(self, event: dict) -> None:
        """Behaviour rules on every query; name models on analysable names.

        Both name models run independently. Deduplication suppresses
        repeated alerts for the same base domain within 60 s.
        """
        domain = event.get("domain", "")
        if not domain:
            return
        source_ip = event.get("source_ip")
        dest_ip = event.get("dest_ip")
        ts = event.get("timestamp")

        # --- behaviour rules: record-type mix, subdomain fan-out ---
        with Timer(self.metrics, "det.dns_behaviour"):
            rule_alerts = self.dns_tracker.observe_query(event)
        for r in rule_alerts:
            self._raise_rule(self.dns_tracker, r, source_ip, dest_ip, {
                "scope": "source", "src_ip": source_ip, "dst_ip": dest_ip,
                "dst_port": 53, "protocol": "UDP", "domain": r.get("domain")})

        if event.get("lexical") is False:
            return   # reverse lookups, .local names: counted above, not scored

        flow_meta = {"scope": "dns_query", "domain": domain, "src_ip": source_ip,
                     "dst_ip": dest_ip, "dst_port": 53, "protocol": "UDP"}
        parts = domain.lower().strip().split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        dga_alert = None
        exfil_alert = None

        # Both name models are pure functions of the name, and real DNS
        # repeats names constantly: their outputs are cached per name.
        cached = self._name_cache.get(domain)
        if cached is None:
            self.name_cache_stats["misses"] += 1
            dga_res = exf_res = dns_base = None
            if self.registry.dga and base_domain not in _DGA_WHITELIST_SLDS:
                with Timer(self.metrics, "det.dga_cnn_bilstm"):
                    dga_res = self.registry.dga.predict(domain)
            if self.registry.exfiltration:
                dns_base = build_dns_features(domain)
                if dns_base:
                    with Timer(self.metrics, "det.exfil_vae"):
                        exf_res = self.registry.exfiltration.predict(dns_base)
            cached = (dga_res, dns_base, exf_res)
            self._name_cache[domain] = cached
            if len(self._name_cache) > 20000:
                self._name_cache.popitem(last=False)
        else:
            self.name_cache_stats["hits"] += 1
            self._name_cache.move_to_end(domain)
        dga_res, dns_base, exf_res = cached

        # --- DGA detection ---
        if dga_res is not None:
            result = dict(dga_res)
            result["all_probs"] = dict(dga_res.get("all_probs") or {})
            model_suspicious = result["is_malicious"] and result["confidence"] >= THRESHOLDS["dga"]
            analysis_str = ".".join(parts[:-1]) if len(parts) > 1 else domain
            freq = Counter(analysis_str)
            total = len(analysis_str)
            entropy = -sum((c/total) * math.log2(c/total) for c in freq.values()) if total > 0 else 0
            if model_suspicious and entropy > 3.0:
                dedup_key = f"dga:{base_domain}:{source_ip}"
                now = event.get("timestamp", 0) or 0
                last_alert_time = self._dns_alert_times.get(dedup_key, 0)
                self._dns_query_counts[dedup_key] = self._dns_query_counts.get(dedup_key, 0) + 1
                if now - last_alert_time <= float(getattr(config, "DNS_MODEL_ALERT_REPEAT_S", 60.0)):
                    self._dns_held[dedup_key] = self._dns_held.get(dedup_key, 0) + 1
                else:
                    self._dns_alert_times[dedup_key] = now
                    result["query_count"] = self._dns_query_counts[dedup_key]
                    result["alerts_suppressed_since_last"] = self._dns_held.pop(dedup_key, 0)
                    result["entropy"] = entropy
                    result["subtype"] = {"dga": "machine-generated name",
                                         "dns_tunnel": "tunnel-like name"}.get(
                                             result.get("class_name"), result.get("class_name", ""))
                    result["query_type"] = event.get("query_type")
                    host = self.dns_tracker.host_summary(source_ip)
                    if host:
                        result["host_dns"] = host
                    dga_alert = self._build_model_alert(result, "dga", domain, source_ip, dest_ip,
                                                        flow_meta, ts, ts)

        # --- Exfiltration detection (DNS tunnel names, VAE) ---
        if exf_res is not None and dns_base:
            dns_features = dict(dns_base)
            # Byte counts: what the simulator supplies, or what the DNS
            # tracker measured for this host and base domain. Never made up.
            fwd_bytes = event.get("total_fwd_bytes")
            bwd_bytes = event.get("total_bwd_bytes")
            if fwd_bytes is None or bwd_bytes is None:
                measured = self.dns_tracker.bytes_for(source_ip, domain)
                if measured:
                    fwd_bytes, bwd_bytes = measured
            if fwd_bytes is not None and bwd_bytes is not None:
                dns_features["total_fwd_bytes"] = fwd_bytes
                dns_features["total_bwd_bytes"] = bwd_bytes

            result = dict(exf_res)
            model_detects = result.get("threat") == "Data Exfiltration"
            high_confidence = result.get("confidence", 0) >= THRESHOLDS["exfiltration"]
            evidence_strong = False
            if model_detects:
                dns_entropy = result.get("dns_entropy", 0)
                subdomain_len = result.get("subdomain_length", 0)
                recon_error = result.get("reconstruction_error", 0)
                evidence_strong = (
                    recon_error > 1.4
                    or (dns_entropy > 4.0 and subdomain_len > 20)
                    or (dns_entropy > 5.0)
                )
            if model_detects and high_confidence and evidence_strong:
                dedup_key = f"exfil:{base_domain}:{source_ip}"
                now = event.get("timestamp", 0) or 0
                last_alert_time = self._dns_alert_times.get(dedup_key, 0)
                self._dns_query_counts[dedup_key] = self._dns_query_counts.get(dedup_key, 0) + 1
                if now - last_alert_time <= float(getattr(config, "DNS_MODEL_ALERT_REPEAT_S", 60.0)):
                    self._dns_held[dedup_key] = self._dns_held.get(dedup_key, 0) + 1
                else:
                    self._dns_alert_times[dedup_key] = now
                    result["query_count"] = self._dns_query_counts[dedup_key]
                    result["alerts_suppressed_since_last"] = self._dns_held.pop(dedup_key, 0)
                    # FIX: when no byte counts existed, this used to invent
                    # them (subdomain length x 50 out, 512 in). byte_ratio is
                    # now present only when bytes were actually measured.
                    result.pop("byte_ratio", None)
                    if fwd_bytes is not None and bwd_bytes is not None:
                        result["byte_ratio"] = {"outbound": int(fwd_bytes), "inbound": int(bwd_bytes)}
                        if event.get("total_fwd_bytes") is None:
                            result["byte_ratio_source"] = "dns_query_and_reply_sizes"
                    result.pop("mitre", None)
                    result["subtype"] = "DNS tunnelling (anomalous name)"
                    result["domain"] = domain
                    result["query_type"] = event.get("query_type")
                    exfil_alert = self._build_model_alert(result, "exfiltration", dns_features,
                                                          source_ip, dest_ip, flow_meta, ts, ts)

        # Exfil alert first (more specific), then DGA
        for a in (exfil_alert, dga_alert):
            if a:
                self._raised.append(a)

    def _build_model_alert(self, result, seal_key, seal_input, source_ip, dest_ip, flow_meta, ev_start, ev_end):
        ctx = dict(self._ctx)
        ctx.update(event_start=ev_start, event_end=ev_end)
        alert = self.alert_manager.create_alert(
            result, source_ip=source_ip, dest_ip=dest_ip, flow_meta=flow_meta, context=ctx)
        if alert:
            self._seal_alert(alert, seal_key, seal_input)
        return alert

    def _analyze_dns_response(self, event: dict) -> None:
        with Timer(self.metrics, "det.dns_behaviour"):
            rule_alerts = self.dns_tracker.observe_response(event)
        for r in rule_alerts:
            self._raise_rule(self.dns_tracker, r, event.get("source_ip"), event.get("dest_ip"), {
                "scope": "source", "src_ip": event.get("source_ip"), "dst_ip": event.get("dest_ip"),
                "dst_port": 53, "protocol": "UDP"})

    # ==================================================================
    # Session path (BiLSTM+FFT) -- evidence for the combined C2 score
    # ==================================================================
    def _analyze_session(self, event: dict) -> None:
        flows = event.get("flows", [])
        if not flows or not self.registry.c2:
            return
        with Timer(self.metrics, "det.c2_bilstm"):
            result = self.registry.c2.predict(flows)
        pair = (event.get("source_ip"), event.get("dest_ip"))
        self.bilstm_by_pair[pair] = {
            "probability": round(float(result.get("confidence", 0.0)), 4),
            "is_beacon": bool(result.get("is_beacon")),
            "periodicity_seconds": round(float(result.get("periodicity_seconds", 0.0)), 2),
            "flows": len(flows),
        }
        if len(self.bilstm_by_pair) > 20000:
            for k in list(self.bilstm_by_pair)[:5000]:
                self.bilstm_by_pair.pop(k, None)
        # The BiLSTM no longer raises alerts on its own (it is evidence for
        # the combined score). C2_BILSTM_ALERTS=True restores the old path.
        if getattr(config, "C2_BILSTM_ALERTS", False) and result["is_beacon"] \
                and result["confidence"] >= THRESHOLDS["c2_beacon"]:
            flow_meta = {"scope": "host_pair", "src_ip": event.get("source_ip"),
                         "dst_ip": event.get("dest_ip"), "protocol": "TCP"}
            self._raise_model(result, "c2", flows, event.get("source_ip"), event.get("dest_ip"),
                              flow_meta, event.get("timestamp"), event.get("timestamp"))

    # ==================================================================
    # Flow path
    # ==================================================================
    def _analyze_flow(self, event: dict) -> None:
        """Flow events feed three groups of detectors.

        Volume detectors (DDoS window/rule, XGBoost, port-scan window) read
        one copy of each flow: CICFlowMeter's in pcap mode, the sensor's own
        (including single-packet stubs) in live mode, the simulator's when
        simulating. Connection detectors (C2 score, byte ratio, TLS) read the
        sensor's own flows, which carry exact start times and TLS metadata.
        """
        features = event.get("features") or {}
        stub = bool(event.get("stub"))
        extractor = event.get("extractor")   # "cicflowmeter", "custom", or None (simulator)
        source_ip = event.get("source_ip")
        dest_ip = event.get("dest_ip")
        ts = event.get("timestamp")
        flow_meta = self._build_flow_meta(event)
        volume_feed = extractor in ("cicflowmeter", None) or (
            extractor == "custom" and not event.get("cic_covered"))
        conn_feed = extractor in ("custom", None) and not stub

        # Track dst ports per source for port-scan fan-out evidence
        dst_port = event.get("dest_port", features.get("dst_port", 0))
        if source_ip and dst_port:
            self._recent_dst_ports[source_ip].add(dst_port)
            if len(self._recent_dst_ports[source_ip]) > 500:
                ports = list(self._recent_dst_ports[source_ip])
                self._recent_dst_ports[source_ip] = set(ports[-200:])

        # --- (a) DDoS ---
        if volume_feed and dest_ip and ts is not None:
            with Timer(self.metrics, "det.ddos_window"):
                self.ddos_tracker.observe(event)
            if extractor != "custom" and not stub and self.registry.ddos and features:
                with Timer(self.metrics, "det.ddos_xgboost"):
                    result = self.registry.ddos.predict(features)
                self.xgb_counts["flows_scored"] += 1
                if result["is_attack"] and result["confidence"] >= THRESHOLDS["ddos"]:
                    # Heuristic guard: real DDoS has high packet/byte rates
                    pkt_rate = features.get("Flow Packets/s", features.get("flow_pkts_s", 0))
                    byte_rate = features.get("Flow Bytes/s", features.get("flow_byts_s", 0))
                    if pkt_rate > 100 or byte_rate > 50000:
                        self.xgb_counts["flagged"] += 1
                        self._ddos_alert(event, result, "xgb", features, flow_meta)
            with Timer(self.metrics, "det.ddos_rule"):
                rule = self.ddos_tracker.evaluate(dest_ip, float(ts))
            if rule:
                self._ddos_alert(event, rule, "rule", None, flow_meta)

        # --- Encrypted-traffic application classifier (telemetry) ---
        if extractor != "cicflowmeter" and not stub and self.registry.ett and features \
                and self._ett_budget():
            with Timer(self.metrics, "det.ett_transformer"):
                result = self.registry.ett.predict(features)
            app = result.get("app_class") or result.get("threat") or "unknown"
            self.ett_classifications[app] = self.ett_classifications.get(app, 0) + 1
            if result["is_vpn"] and result["confidence"] >= THRESHOLDS["encrypted_malware"] and ETT_ALERT_ON_VPN:
                self._raise_model(result, "ett", features, source_ip, dest_ip, flow_meta,
                                  ts, event.get("last_seen", ts))
            # else: tunnelled-application classification is telemetry,
            # not a threat -- see ETT_ALERT_ON_VPN in config.py.

        # --- (e) Port scan / host sweep (network-event aggregation) ---
        # Multicast and broadcast traffic (mDNS, SSDP, LLMNR, DHCP) is never
        # answered by the group address, so to the network-event model every
        # such flow looks like an unanswered probe of a host that does not
        # exist. On real traffic that made service discovery the main source
        # of "port scans"; those flows are left out of the scan window.
        # A client's web, DNS, NTP, DoT and mDNS traffic to the internet is
        # left out too (the list the host-sweep backstop already ignores):
        # the tree reads every flow as unanswered, as in its one-way NetFlow
        # training data, so a browsing burst to 52+ servers in a minute
        # otherwise reads as a sweep.
        if volume_feed and features and is_group_destination(dest_ip):
            self.portscan_rule.skipped_group += 1
        elif (volume_feed and features and dest_ip and not is_internal(dest_ip)
              and dst_port in self.portscan_router.detector.sweep_exempt):
            self.portscan_rule.skipped_external_service += 1
        elif volume_feed and features:
            # FIX (2026-09-20): buffer the flow's IDENTITY alongside its
            # features -- Flow.from_cic_record() needs Src/Dst IP, Dst Port
            # and Timestamp, which live at the event level.
            rec = dict(features)
            rec.setdefault("Src IP", source_ip)
            rec.setdefault("Dst IP", dest_ip)
            rec.setdefault("Src Port", event.get("source_port", 0))
            rec.setdefault("Dst Port", dst_port)
            rec.setdefault("Timestamp", ts if ts is not None else 0.0)
            rec.setdefault("Protocol", event.get("protocol", features.get("Protocol", 6)))
            self._cic_flow_buffer.append(rec)
            current_time = float(ts) if ts is not None else 0.0
            # _last_flush_time starts at 0.0: anchor on first sight so the
            # first flow of a capture is not flushed alone.
            if not self._last_flush_time:
                self._last_flush_time = current_time
            if (current_time - self._last_flush_time >= 60.0
                    or len(self._cic_flow_buffer) >= 1000):
                self._flush_portscan(current_time, current_source=source_ip)

        # --- (b) C2, (f) byte-ratio exfiltration, (d) TLS sessions ---
        if conn_feed and ts is not None and source_ip and dest_ip:
            host_pair = {"scope": "host_pair", "src_ip": source_ip, "dst_ip": dest_ip,
                         "dst_port": dst_port, "protocol": flow_meta["protocol"]}
            with Timer(self.metrics, "det.c2_combined"):
                r = self.beacon.observe(event)
            if r:
                self._c2_alert(event, r, host_pair)
            with Timer(self.metrics, "det.exfil_ratio"):
                r = self.exfil_ratio.observe(event)
            if r:
                self._raise_rule(self.exfil_ratio, r, source_ip, dest_ip, host_pair)
            if event.get("tls"):
                with Timer(self.metrics, "det.tls_sessions"):
                    r = self.tls_detector.observe(event)
                if r:
                    self._raise_rule(self.tls_detector, r, source_ip, dest_ip, host_pair)

    def _ett_budget(self) -> bool:
        """Token bucket for the telemetry-only application classifier."""
        cap = getattr(config, "ETT_MAX_PER_SECOND", 0) or 0
        self.ett_counts["flows"] += 1
        if cap <= 0:
            self.ett_counts["classified"] += 1
            return True
        now = time.monotonic()
        self._ett_tokens = min(float(cap), self._ett_tokens + (now - self._ett_last) * cap)
        self._ett_last = now
        if self._ett_tokens >= 1.0:
            self._ett_tokens -= 1.0
            self.ett_counts["classified"] += 1
            return True
        self.ett_counts["skipped_load"] += 1
        return False

    def _ddos_alert(self, event, result, path, seal_features, flow_meta):
        dst = event.get("dest_ip")
        ts = float(event.get("timestamp"))
        summary = self.ddos_tracker.summary(dst) or {}
        if path == "xgb" and (summary.get("flows_in_window") or 0) < MIN_FLOWS_FOR_FAMILY:
            # One flagged flow is not a denial of service: a lone SYN probe
            # and a lone SYN-flood packet look the same to a per-flow model.
            # Wait until the destination's window holds enough flows to show
            # a flood (a real one fills it within a fraction of a second).
            self.xgb_counts["held_thin_window"] = self.xgb_counts.get("held_thin_window", 0) + 1
            return None
        if path == "xgb" and summary.get("looks_like_scan"):
            # One source spread over many ports is a scan, not a flood: the
            # port-scan detector owns it. (The per-flow XGBoost cannot tell
            # a lone SYN probe from a lone SYN-flood packet.)
            self.xgb_counts["suppressed_as_scan"] = self.xgb_counts.get("suppressed_as_scan", 0) + 1
            return None
        family = summary.get("family")
        if family is None and path == "xgb":
            family = flow_family(event)
            if family:
                summary["family_basis"] = "flow"
        family = family or "unclassified flood"
        summary["family"] = family
        prev = self._ddos_victims.get(dst)
        srcs = self.ddos_tracker.sources(dst, 5000)
        if prev is not None and ts - prev[0] <= 120.0 and len(prev[1]) < 5000:
            srcs |= prev[1]
        self._ddos_victims[dst] = (ts, srcs)
        if len(self._ddos_victims) > 5000:
            self._ddos_victims.pop(next(iter(self._ddos_victims)))
        ok, held = self.ddos_cooldown.allow((dst, family), ts)
        if not ok:
            self.ddos_tracker.suppressed += 1
            return None
        window_ev = {k: v for k, v in summary.items() if not k.startswith("_")}
        if path == "xgb":
            r = dict(result)
            # The binary XGBoost says DDoS / not DDoS only; the attack family
            # comes from the destination's window (protocol, flags, ports).
            r["subtype"] = family + (" (spoofed sources likely)" if summary.get("spoofed_sources_likely") else "")
            r.pop("attack_type", None)
            r.update(window_ev)
            r["flows_flagged_since_last_alert"] = held
            multi = getattr(self.registry.ddos, "multiclass_label", None)
            if callable(multi):
                label = multi(seal_features)
                if label:
                    r["multiclass_model_label"] = label
            return self._raise_model(r, "ddos", seal_features, event.get("source_ip"), dst, flow_meta,
                                     summary.get("_event_start", ts), summary.get("_event_end", ts))
        r = dict(result)
        r["alerts_suppressed_since_last"] = held
        proto = "UDP" if (summary.get("udp_share") or 0) >= 0.5 else "TCP"
        port = summary.get("top_dst_port") if (summary.get("top_dst_port_share") or 0) >= 0.5 else None
        meta = {"scope": "destination", "src_ip": None, "dst_ip": dst, "dst_port": port, "protocol": proto}
        return self._raise_rule(self.ddos_tracker, r, None, dst, meta)

    def _c2_alert(self, event, r, host_pair):
        src, dst = event.get("source_ip"), event.get("dest_ip")
        if self.registry.c2 is not None:
            series = self.beacon.model_series(src, dst, float(event["timestamp"]))
            if len(series) >= 20:
                with Timer(self.metrics, "det.c2_bilstm"):
                    m = self.registry.c2.predict(series)
                r["bilstm"] = {"probability": round(float(m.get("confidence", 0.0)), 4),
                               "is_beacon": bool(m.get("is_beacon")),
                               "note": "BiLSTM+FFT verdict on the same check-ins; evidence, not the decision"}
        if (src, dst) in self.bilstm_by_pair:
            r["bilstm_session"] = self.bilstm_by_pair[(src, dst)]
        meta = dict(host_pair)
        meta["dst_port"] = r.get("dst_port", host_pair.get("dst_port"))
        self._raise_rule(self.beacon, r, src, dst, meta)

    def _flush_portscan(self, current_time: float, current_source=None) -> None:
        try:
            self.portscan_rule.runs += 1
            with Timer(self.metrics, "det.portscan_window"):
                ps_alerts = self.portscan_router.handle_batch(
                    self._cic_flow_buffer, legacy_flow_model=self.registry.port_scan)
            for ps_alert in ps_alerts:
                self._raise_portscan(ps_alert)
        except Exception as e:
            # Log but don't crash - graceful degradation
            print(f"[ERROR] Port scan aggregation failed: {e}")
            import traceback
            traceback.print_exc()
        self._cic_flow_buffer.clear()
        self._last_flush_time = current_time

    def _raise_portscan(self, ps_alert: dict):
        src = ps_alert.get("src_ip")
        dst = ps_alert.get("dst_ip")
        if dst in (None, "", "multiple", "None"):
            dst = None
        # During a DDoS the flood's sources (reflectors answering to random
        # ports, spoofed SYNs) also look like scanners of the victim. The
        # DDoS alert already covers them; do not add one "scan" per source.
        ws = float(ps_alert.get("window_start") or 0.0)
        hit = self._ddos_victims.get(dst) if dst else None
        if hit is not None and abs(ws - hit[0]) <= 120.0 and src in hit[1]:
            self.portscan_rule.suppressed += 1
            return None
        # One alert per source and window: the buffer is also flushed every
        # 1,000 flows, so a busy window can be evaluated more than once.
        wkey = (src, ws)
        if wkey in self._portscan_alerted:
            self.portscan_rule.suppressed += 1
            return None
        self._portscan_alerted[wkey] = True
        if len(self._portscan_alerted) > 50000:
            for k in list(self._portscan_alerted)[:10000]:
                self._portscan_alerted.pop(k, None)
        ev = ps_alert.get("evidence") or {}
        r = dict(ps_alert)
        r.pop("mitre", None)
        window = float(self.portscan_router.detector.builder.window)
        ws = float(ps_alert.get("window_start") or 0.0)
        horizontal = ps_alert.get("scan_type") == "horizontal"
        meta = {"scope": "source", "src_ip": src, "dst_ip": None if horizontal else dst,
                "dst_port": ev.get("sweep_port") if horizontal else None, "protocol": "TCP"}
        inputs = {k: ev.get(k, 0) for k in ("icmp_error", "rst", "rwa", "neip", "netcp", "succession")}
        inputs.update(fanout=ev.get("distinct_ports", 0), sweep_port=ev.get("sweep_port"),
                      sweep_hosts=ev.get("sweep_hosts", 0))
        r["_event_start"], r["_event_end"] = ws, ws + window
        r["_replay_inputs"] = inputs
        # The tree's probability, or a backstop's fixed 0.9 when only a
        # fan-out / sweep threshold fired.
        tree_fired = any(k in str(ps_alert.get("reason") or "") for k in ("neip=", "UPSD"))
        r["confidence_kind"] = "model_probability" if tree_fired else "rule_score"
        self.portscan_rule.alerts += 1
        return self._raise_rule(self.portscan_rule, r, src, meta["dst_ip"], meta)

    def flush_portscan_buffer(self) -> list[dict]:
        """Flush any remaining buffered flows for port-scan detection.

        Call at the end of a capture or replay. Returns the alerts raised.
        """
        self._raised = []
        self._ctx = {"t0_perf": time.perf_counter(), "ingest_wall": None}
        if self._cic_flow_buffer:
            self._flush_portscan(self._last_wire_ts or 0.0, current_source=None)
        return list(self._raised)

    # ==================================================================
    # Integrity hooks
    # ==================================================================
    def _seal_alert(self, alert: dict, model_key: str, features_or_input) -> None:
        """Additive integrity hook for model alerts — sign receipt + store blob.

        Never raises — if anything fails, it logs and continues.
        """
        if not self._integrity or not alert:
            return
        try:
            from netsentinel.integrity.encoding import confidence_to_ppm
            from netsentinel.integrity.receipt import ProvenanceResult

            svc = self._integrity
            model = getattr(self.registry, model_key, None)
            if model is None:
                return
            if hasattr(model, "predict_with_provenance"):
                _, prov = model.predict_with_provenance(features_or_input)
            else:
                prov = ProvenanceResult(
                    prediction_class=alert.get("threat_class", "Unknown"),
                    score_ppm=confidence_to_ppm(alert.get("confidence", 0)),
                    feature_names=[], feature_values=[], preprocessor_ref=None,
                )
            statement = svc["receipt_builder"].build(
                alert=alert, provenance=prov,
                model_digest=self.registry.model_digest(model_key),
                model_version=alert.get("model_name", "unknown"),
                sensor_ctx=svc["sensor_ctx"],
            )
            envelope = svc["sign_receipt"](statement, svc["signing_key"])
            alert["receipt_ref"] = svc["envelope_digest"](envelope)
            svc["anchor_service"].add_envelope(alert["id"], envelope)
            feature_blob = {"names": list(prov.feature_names), "values": list(prov.feature_values)}
            if model_key == "dga":
                feature_blob["domain"] = features_or_input
            elif model_key == "c2":
                feature_blob["flows"] = features_or_input
            svc["blob_store"].put(alert["id"], feature_blob, alert.get("evidence", {}))
        except Exception as e:
            print(f"  [INTEGRITY] Seal failed for {alert.get('id', '?')}: {e}")

    def _seal_rule(self, alert: dict, detector, inputs) -> None:
        """Integrity hook for rule/statistical detectors.

        The receipt commits to the detector's parameter digest (in place of a
        model file digest) and to the exact numbers the decision was made
        from, stored as one canonical JSON string so replay can recompute it.
        """
        if not self._integrity or not alert or inputs is None:
            return
        try:
            from netsentinel.integrity.encoding import confidence_to_ppm
            from netsentinel.integrity.receipt import ProvenanceResult
            svc = self._integrity
            blob = json.dumps(inputs, sort_keys=True, separators=(",", ":"), default=str)
            prov = ProvenanceResult(
                prediction_class=alert.get("threat_class", "Unknown"),
                score_ppm=confidence_to_ppm(alert.get("confidence", 0.0)),
                feature_names=["rule_inputs"], feature_values=[blob], preprocessor_ref=None,
            )
            statement = svc["receipt_builder"].build(
                alert=alert, provenance=prov, model_digest=detector.digest,
                model_version=f"rules:{detector.key}:{detector.version}",
                sensor_ctx=svc["sensor_ctx"],
            )
            envelope = svc["sign_receipt"](statement, svc["signing_key"])
            alert["receipt_ref"] = svc["envelope_digest"](envelope)
            svc["anchor_service"].add_envelope(alert["id"], envelope)
            svc["blob_store"].put(alert["id"], {"names": ["rule_inputs"], "values": [blob],
                                                "rule_key": detector.key}, alert.get("evidence", {}))
        except Exception as e:
            print(f"  [INTEGRITY] Seal failed for {alert.get('id', '?')}: {e}")

    # ==================================================================
    # Introspection
    # ==================================================================
    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            "flows_processed": self.flows_processed,
            "ett_classifications": dict(self.ett_classifications),
            "ett_counts": dict(self.ett_counts),
            "dns_name_cache": dict(self.name_cache_stats),
            "ddos_xgboost": dict(self.xgb_counts),
            **self.alert_manager.get_stats(),
        }

    def detector_catalog(self) -> list[dict]:
        """Every detector, what it covers, and its live counters."""
        lat = self.metrics.snapshot(with_series=False)["latency_ms"]["detector"]
        rows = []
        for key, d in self.rules.items():
            info = d.describe()
            info["latency_ms"] = {k: v for k, v in lat.items() if k.startswith(_LAT_PREFIX.get(key, key))}
            rows.append(info)
        return rows

    def c2_watchlist(self, n: int = 5) -> list:
        return self.beacon.top(n)


_LAT_PREFIX = {"ddos_rate_entropy": "ddos", "dns_behaviour": "dns_behaviour", "c2_combined": "c2",
               "tls_sessions": "tls_sessions", "exfil_ratio": "exfil_ratio", "port_scan": "portscan"}


# ======================================================================
# Utility functions
# ======================================================================

def _proto_name(proto) -> str:
    """Convert numeric protocol to string."""
    if isinstance(proto, str):
        return proto
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "TCP")


def _shannon_entropy_of_ips(ip_list: list[str]) -> float:
    """Shannon entropy (bits) of an IP address distribution."""
    if not ip_list:
        return 0.0
    freq = Counter(ip_list)
    total = len(ip_list)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())
