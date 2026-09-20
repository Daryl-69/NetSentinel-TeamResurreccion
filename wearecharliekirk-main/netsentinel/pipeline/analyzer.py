"""Flow Analyzer — Routes incoming events to the correct AI models.

This is the central orchestrator. It receives raw "events" from the 
traffic simulator or extraction layer and routes them to the appropriate
model(s). Supports all 6 detection classes:

  - DDoS (flow path)
  - Encrypted Traffic / VPN (flow path)
  - Port Scan (flow path, network-event aggregation)
  - DGA (DNS path)
  - Data Exfiltration / DNS Tunnel (DNS path, requires lexical features)
  - C2 Beacon (session path)
"""
import math
from collections import Counter, defaultdict

from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.config import THRESHOLDS, ETT_ALERT_ON_VPN
from netsentinel.extractor.unsw_feature_builder import (
    build_unsw_features,
    ConnectionTracker,
)
from netsentinel.extractor.dns_feature_builder import build_dns_features
from netsentinel.pipeline.portscan_integration import PortScanRouter
import netsentinel.config as config


class FlowAnalyzer:
    """Routes flows to models and collects alerts."""
    
    def __init__(self, registry: ModelRegistry, alert_manager: AlertManager,
                 integrity_services: dict | None = None):
        self.registry = registry
        self.alert_manager = alert_manager
        self.flows_processed = 0
        # application-class telemetry from the ETT (not alerts)
        self.ett_classifications: dict[str, int] = {}

        # Integrity layer (None = disabled, degrades gracefully)
        self._integrity = integrity_services

        # Connection tracker for UNSW-NB15 ct_* features (port scan)
        self._conn_tracker = ConnectionTracker()

        # DDoS evidence: track recent source IPs per destination for entropy
        self._recent_src_ips: dict[str, list[str]] = defaultdict(list)
        _MAX_SRC_IP_WINDOW = 200  # Track last 200 source IPs per target

        # Port scan evidence: track recent dst ports per source IP
        self._recent_dst_ports: dict[str, set[int]] = defaultdict(set)

        # DNS alert deduplication: suppress repeated alerts for same base domain
        self._dns_alert_times: dict[str, float] = {}  # dedup_key → last alert timestamp
        self._dns_query_counts: dict[str, int] = {}   # dedup_key → total query count

        # Port scan router: network-event aggregation detector (process-lifetime instance)
        # Succession state (slow-scan) and UPSD likelihood ratios persist across batches
        self.portscan_router = PortScanRouter(
            network_info_path=config.portscan.network_info_path,
            cfg=config,
        )
        
        # CICFlowMeter batch buffer for network-event aggregation
        self._cic_flow_buffer: list[dict] = []
        self._last_flush_time = 0.0
    
    def analyze_flow(self, event: dict) -> dict | None:
        """
        Analyze a single event and return an alert if threat detected.
        
        Events can be:
          - type="flow": Network flow with statistical features → DDoS + ETT + Port Scan
          - type="dns": DNS query → DGA + Exfiltration
          - type="session": Time-series of flows → C2 Beacon
        
        Args:
            event: dict with "type" key and model-specific data
        
        Returns:
            Alert dict if threat detected, None otherwise
        """
        # PacketProcessor.process_pcap() yields None every 1000 packets as a
        # cooperative-yield signal (pcap_reader.py:191). routes.py skips those,
        # but any other caller would hit AttributeError here -- and a None would
        # also inflate flows_processed. Guard before counting.
        if not event:
            return None

        self.flows_processed += 1
        event_type = event.get("type", "flow")
        
        if event_type == "dns" and (self.registry.dga or self.registry.exfiltration):
            return self._analyze_dns(event)
        elif event_type == "session" and self.registry.c2:
            return self._analyze_session(event)
        elif event_type == "flow":
            return self._analyze_flow(event)
        
        return None
    
    def _build_flow_meta(self, event: dict) -> dict:
        """Build 5-tuple flow_meta from event fields.
        
        The flow extractor emits source_port, dest_port, protocol at the
        top level of the event dict. The simulator puts them in features.
        We check both locations.
        """
        features = event.get("features", {})
        return {
            "src_ip":   event.get("source_ip"),
            "src_port": event.get("source_port", features.get("src_port", 0)),
            "dst_ip":   event.get("dest_ip"),
            "dst_port": event.get("dest_port", features.get("dst_port", 0)),
            "protocol": _proto_name(event.get("protocol", features.get("Protocol", 6))),
        }

    def _analyze_dns(self, event: dict) -> dict | None:
        """Run DGA detection + exfiltration detection on a DNS query.
        
        Both detectors run independently. Deduplication prevents alert spam
        by suppressing repeated alerts for the same base domain within a window.
        """
        domain = event.get("domain", "")
        if not domain:
            return None
        
        source_ip = event.get("source_ip")
        dest_ip = event.get("dest_ip")
        # The resolver the query went to is the actionable destination for a
        # DNS-tunnelling alert; without it the alert cannot be triaged.
        flow_meta = {"domain": domain, "src_ip": source_ip, "dst_ip": dest_ip}
        
        # Extract base domain for deduplication (e.g., "xxx.www.ggy666.tk" → "ggy666.tk")
        parts = domain.lower().strip().split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        dga_alert = None
        exfil_alert = None

        # --- DGA detection ---
        if self.registry.dga:
            # Whitelist: skip known-good domains that trigger false positives
            # due to random-looking subdomains (e.g., r20swj13mr.microsoft.com)
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
                "w3.org", "wikipedia.org", "mozilla.org", "mozilla.net",
                "ubuntu.com", "debian.org", "centos.org",
                "windowsupdate.com", "update.microsoft.com",
            }
            if base_domain in _DGA_WHITELIST_SLDS:
                pass  # Skip whitelisted domain entirely
            else:
                result = self.registry.dga.predict(domain)
            
                # Signal 1: Model prediction
                model_suspicious = result["is_malicious"] and result["confidence"] >= THRESHOLDS["dga"]
                
                # Signal 2: Entropy analysis
                analysis_str = ".".join(parts[:-1]) if len(parts) > 1 else domain
                freq = Counter(analysis_str)
                total = len(analysis_str)
                entropy = -sum((c/total) * math.log2(c/total) for c in freq.values()) if total > 0 else 0
                high_entropy = entropy > 3.0
                
                if model_suspicious and high_entropy:
                    # Deduplication: only alert once per base domain per 60s window
                    dedup_key = f"dga:{base_domain}:{source_ip}"
                    now = event.get("timestamp", 0)
                    last_alert_time = self._dns_alert_times.get(dedup_key, 0)
                    
                    if now - last_alert_time > 60.0:
                        self._dns_alert_times[dedup_key] = now
                        # Count how many queries we've seen for this domain
                        self._dns_query_counts[dedup_key] = self._dns_query_counts.get(dedup_key, 0) + 1
                        result["query_count"] = self._dns_query_counts[dedup_key]
                        result["entropy"] = entropy
                        dga_alert = self.alert_manager.create_alert(
                            result,
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            flow_meta=flow_meta,
                        )
                        self._seal_alert(dga_alert, "dga", domain)
                    else:
                        # Suppress duplicate, but still count
                        self._dns_query_counts[dedup_key] = self._dns_query_counts.get(dedup_key, 0) + 1

        # --- Exfiltration detection (DNS tunnel) ---
        if self.registry.exfiltration:
            dns_features = build_dns_features(domain)
            if dns_features:
                # Add byte counts if available
                fwd_bytes = event.get("total_fwd_bytes")
                bwd_bytes = event.get("total_bwd_bytes")
                if fwd_bytes is None:
                    fwd_bytes = event.get("features", {}).get("Fwd Packets Length Total")
                if bwd_bytes is None:
                    bwd_bytes = event.get("features", {}).get("Bwd Packets Length Total")
                if fwd_bytes is not None and bwd_bytes is not None:
                    dns_features["total_fwd_bytes"] = fwd_bytes
                    dns_features["total_bwd_bytes"] = bwd_bytes
                
                result = self.registry.exfiltration.predict(dns_features)
                
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
                    # Deduplication for exfil too
                    dedup_key = f"exfil:{base_domain}:{source_ip}"
                    now = event.get("timestamp", 0)
                    last_alert_time = self._dns_alert_times.get(dedup_key, 0)
                    
                    if now - last_alert_time > 60.0:
                        self._dns_alert_times[dedup_key] = now
                        # Add byte_ratio for frontend
                        fwd = dns_features.get("total_fwd_bytes", 0)
                        bwd = dns_features.get("total_bwd_bytes", 0)
                        if fwd or bwd:
                            result["byte_ratio"] = {"outbound": int(fwd), "inbound": int(bwd)}
                        elif subdomain_len > 0:
                            result["byte_ratio"] = {"outbound": int(subdomain_len * 50), "inbound": 512}
                        
                        exfil_alert = self.alert_manager.create_alert(
                            result,
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            flow_meta=flow_meta,
                        )
                        self._seal_alert(exfil_alert, "exfiltration", dns_features)

        # Return exfil alert preferentially (more specific), fallback to DGA
        return exfil_alert or dga_alert
    
    def _analyze_session(self, event: dict) -> dict | None:
        """Run C2 Beacon detection on a flow time-series."""
        flows = event.get("flows", [])
        if not flows:
            return None
        
        # Build flow_meta for the session
        flow_meta = {
            "src_ip":   event.get("source_ip"),
            "src_port": 0,
            "dst_ip":   event.get("dest_ip"),
            "dst_port": 0,
            "protocol": "TCP",
        }
        
        result = self.registry.c2.predict(flows)
        
        if result["is_beacon"] and result["confidence"] >= THRESHOLDS["c2_beacon"]:
            c2_alert = self.alert_manager.create_alert(
                result,
                source_ip=event.get("source_ip"),
                dest_ip=event.get("dest_ip"),
                flow_meta=flow_meta,
            )
            self._seal_alert(c2_alert, "c2", flows)
            return c2_alert
        return None
    
    def _analyze_flow(self, event: dict) -> dict | None:
        """Run DDoS, ETT, and/or Port Scan detection on a single flow.

        Hybrid routing based on extractor source:
          - extractor="cicflowmeter" → DDoS + Port Scan (zero-drift CIC features)
          - extractor="custom"       → ETT only (custom ISCX features)
          - no tag (simulator/legacy) → all models (backward compatible)
        """
        features = event.get("features", {})
        flow_meta = self._build_flow_meta(event)
        source_ip = event.get("source_ip")
        dest_ip = event.get("dest_ip")
        alert = None

        # Which extractor produced this event?
        extractor = event.get("extractor")  # "cicflowmeter", "custom", or None
        
        # Track source IPs per destination for DDoS entropy evidence
        if dest_ip and source_ip:
            src_list = self._recent_src_ips[dest_ip]
            src_list.append(source_ip)
            if len(src_list) > 200:
                self._recent_src_ips[dest_ip] = src_list[-200:]

        # Track dst ports per source for port-scan fan-out evidence
        dst_port = event.get("dest_port", features.get("dst_port", 0))
        if source_ip and dst_port:
            self._recent_dst_ports[source_ip].add(dst_port)
            # Cap the set size
            if len(self._recent_dst_ports[source_ip]) > 500:
                ports = list(self._recent_dst_ports[source_ip])
                self._recent_dst_ports[source_ip] = set(ports[-200:])

        # --- DDoS detection (CICFlowMeter features or untagged) ---
        if extractor != "custom":  # cicflowmeter or None (legacy/simulator)
            if self.registry.ddos and features:
                result = self.registry.ddos.predict(features)
                if result["is_attack"] and result["confidence"] >= THRESHOLDS["ddos"]:
                    # Heuristic guard: real DDoS has high packet/byte rates
                    pkt_rate = features.get("Flow Packets/s", features.get("flow_pkts_s", 0))
                    byte_rate = features.get("Flow Bytes/s", features.get("flow_byts_s", 0))
                    if pkt_rate > 100 or byte_rate > 50000:
                        # Add src_ip_entropy evidence
                        if dest_ip and dest_ip in self._recent_src_ips:
                            src_entropy = _shannon_entropy_of_ips(
                                self._recent_src_ips[dest_ip]
                            )
                            result["src_ip_entropy"] = round(src_entropy, 2)

                        alert = self.alert_manager.create_alert(
                            result,
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            flow_meta=flow_meta,
                        )
                        self._seal_alert(alert, "ddos", features)
        
        # --- Encrypted traffic detection (custom features or untagged) ---
        if extractor != "cicflowmeter":  # custom or None (legacy/simulator)
            if alert is None and self.registry.ett and features:
                result = self.registry.ett.predict(features)
                # Record the application class as telemetry regardless.
                app = result.get("app_class") or result.get("threat") or "unknown"
                self.ett_classifications[app] = self.ett_classifications.get(app, 0) + 1
                if (result["is_vpn"]
                        and result["confidence"] >= THRESHOLDS["encrypted_malware"]):
                    if ETT_ALERT_ON_VPN:
                        alert = self.alert_manager.create_alert(
                            result,
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            flow_meta=flow_meta,
                        )
                        self._seal_alert(alert, "ett", features)
                    # else: tunnelled-application classification is telemetry,
                    # not a threat -- see ETT_ALERT_ON_VPN in config.py.

        # --- Port Scan detection (Network-Event Aggregation) ---
        # The new approach: buffer CICFlowMeter flows and process them in
        # batches per time window (60s default) using network-event aggregation.
        # This detects cross-flow patterns (many ports, non-existent IPs, etc.)
        # that the old per-flow XGBoost model missed entirely.
        #
        # The old per-flow model is optionally kept as a non-driving
        # ml_flow_score field for supplementary display only.
        if extractor != "custom":  # cicflowmeter or None (legacy/simulator)
            if features:
                # Buffer this flow for batch processing.
                #
                # FIX (2026-09-20): buffer the flow's IDENTITY alongside its
                # features. Flow.from_cic_record() needs Src/Dst IP, Dst Port
                # and Timestamp to group flows by source and count fan-out --
                # but those live at the EVENT level, not inside `features`.
                # Appending `features` alone produced records whose src_ip was
                # the literal string "None" and whose dst_port was 0, which
                # collapsed every flow into one fake source with a single port.
                # Fan-out was therefore always 1 and NO scan could ever fire:
                # port-scan recall was a hard 0%, independent of the model.
                # setdefault() so real CICFlowMeter records that already carry
                # these columns are never overwritten.
                rec = dict(features)
                rec.setdefault("Src IP", source_ip)
                rec.setdefault("Dst IP", dest_ip)
                rec.setdefault("Src Port", event.get("source_port", 0))
                rec.setdefault("Dst Port", dst_port)
                rec.setdefault("Timestamp", event.get("timestamp", 0.0))
                rec.setdefault(
                    "Protocol",
                    event.get("protocol", features.get("Protocol", 6)),
                )
                self._cic_flow_buffer.append(rec)

                # Flush buffer every ~60 seconds (time_window_seconds) or when buffer gets large
                current_time = event.get("timestamp", 0)
                # FIX: _last_flush_time starts at 0.0, so on the first real
                # event `current_time - 0.0` is ~1.7e9 -- always >= 60 -- which
                # forced an immediate flush of a 1-flow buffer and discarded
                # the first flow of every capture. Anchor on first sight.
                if not self._last_flush_time:
                    self._last_flush_time = current_time
                buffer_size = len(self._cic_flow_buffer)
                time_since_flush = current_time - self._last_flush_time
                
                # Flush conditions: 60s elapsed OR buffer > 1000 flows OR this is last flow in a batch
                should_flush = (
                    time_since_flush >= 60.0 or
                    buffer_size >= 1000
                )
                
                if should_flush and self._cic_flow_buffer:
                    # Process batch through network-event aggregation
                    try:
                        ps_alerts = self.portscan_router.handle_batch(
                            self._cic_flow_buffer,
                            legacy_flow_model=self.registry.port_scan
                        )
                        
                        for ps_alert in ps_alerts:
                            # Port scan overrides DDoS (more specific diagnosis)
                            alert = self.alert_manager.create_alert(
                                ps_alert,
                                source_ip=ps_alert.get("src_ip"),
                                dest_ip=ps_alert.get("dst_ip"),
                                flow_meta={
                                    "src_ip": ps_alert.get("src_ip"),
                                    "dst_ip": ps_alert.get("dst_ip"),
                                    "protocol": "TCP",
                                },
                            )
                            # If this current flow triggered a scan alert, return it immediately
                            if ps_alert.get("src_ip") == source_ip:
                                # Clear buffer and reset timer
                                self._cic_flow_buffer.clear()
                                self._last_flush_time = current_time
                                return alert
                    except Exception as e:
                        # Log but don't crash - graceful degradation
                        print(f"[ERROR] Port scan aggregation failed: {e}")
                        import traceback
                        traceback.print_exc()
                    
                    # Clear buffer after processing
                    self._cic_flow_buffer.clear()
                    self._last_flush_time = current_time


        
        return alert

    def _seal_alert(
        self,
        alert: dict,
        model_key: str,
        features_or_input,
    ) -> None:
        """Additive integrity hook — sign receipt + store blob.

        Called after every alert creation.  Never raises — if anything
        fails, it logs and continues (detection > integrity).
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

            # Capture provenance via the model wrapper
            if hasattr(model, "predict_with_provenance"):
                if model_key == "dga":
                    domain = features_or_input
                    _, prov = model.predict_with_provenance(domain)
                elif model_key == "c2":
                    flows = features_or_input
                    _, prov = model.predict_with_provenance(flows)
                else:
                    _, prov = model.predict_with_provenance(features_or_input)
            else:
                # Fallback — create minimal provenance
                prov = ProvenanceResult(
                    prediction_class=alert.get("threat_class", "Unknown"),
                    score_ppm=confidence_to_ppm(alert.get("confidence", 0)),
                    feature_names=[],
                    feature_values=[],
                    preprocessor_ref=None,
                )

            model_digest = self.registry.model_digest(model_key)
            model_version = alert.get("model_name", "unknown")

            # Build receipt
            statement = svc["receipt_builder"].build(
                alert=alert,
                provenance=prov,
                model_digest=model_digest,
                model_version=model_version,
                sensor_ctx=svc["sensor_ctx"],
            )

            # Sign envelope
            envelope = svc["sign_receipt"](statement, svc["signing_key"])

            # Get envelope digest for receipt_ref
            envelope_dig = svc["envelope_digest"](envelope)
            alert["receipt_ref"] = envelope_dig

            # Add to anchor service
            svc["anchor_service"].add_envelope(alert["id"], envelope)

            # Store feature + evidence blobs
            feature_blob = {
                "names": list(prov.feature_names),
                "values": list(prov.feature_values),
            }
            if model_key == "dga":
                feature_blob["domain"] = features_or_input
            elif model_key == "c2":
                feature_blob["flows"] = features_or_input

            evidence_blob = alert.get("evidence", {})
            svc["blob_store"].put(alert["id"], feature_blob, evidence_blob)

        except Exception as e:
            # Never crash the pipeline — detection > integrity
            print(f"  [INTEGRITY] Seal failed for {alert.get('id', '?')}: {e}")
    
    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            "flows_processed": self.flows_processed,
            "ett_classifications": dict(self.ett_classifications),
            **self.alert_manager.get_stats(),
        }
    
    def flush_portscan_buffer(self) -> list[dict]:
        """Flush any remaining CICFlowMeter flows for port scan detection.
        
        Call this at the end of a capture session or PCAP replay to ensure
        all buffered flows are processed through network-event aggregation.
        
        Returns:
            List of alert dicts for any detected scans in the final batch.
        """
        if not self._cic_flow_buffer:
            return []
        
        try:
            ps_alerts = self.portscan_router.handle_batch(
                self._cic_flow_buffer,
                legacy_flow_model=self.registry.port_scan
            )
            self._cic_flow_buffer.clear()
            
            alerts = []
            for ps_alert in ps_alerts:
                alert = self.alert_manager.create_alert(
                    ps_alert,
                    source_ip=ps_alert.get("src_ip"),
                    dest_ip=ps_alert.get("dst_ip"),
                    flow_meta={
                        "src_ip": ps_alert.get("src_ip"),
                        "dst_ip": ps_alert.get("dst_ip"),
                        "protocol": "TCP",
                    },
                )
                alerts.append(alert)
            return alerts
        except Exception as e:
            print(f"[ERROR] Port scan buffer flush failed: {e}")
            import traceback
            traceback.print_exc()
            self._cic_flow_buffer.clear()
            return []


# ======================================================================
# Utility functions
# ======================================================================

def _proto_name(proto) -> str:
    """Convert numeric protocol to string."""
    if isinstance(proto, str):
        return proto
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "TCP")


def _shannon_entropy_of_ips(ip_list: list[str]) -> float:
    """Compute Shannon entropy (bits) of an IP address distribution.
    
    High entropy = many distinct sources (amplified DDoS).
    Low entropy = few sources (single-source flood).
    """
    if not ip_list:
        return 0.0
    freq = Counter(ip_list)
    total = len(ip_list)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())
