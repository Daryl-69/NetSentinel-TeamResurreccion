"""Flow Analyzer — Routes incoming events to the correct AI models.

This is the central orchestrator. It receives raw "events" from the 
traffic simulator or extraction layer and routes them to the appropriate
model(s). Supports all 6 detection classes:

  - DDoS (flow path)
  - Encrypted Traffic / VPN (flow path)
  - Port Scan (flow path, requires UNSW-NB15 features)
  - DGA (DNS path)
  - Data Exfiltration / DNS Tunnel (DNS path, requires lexical features)
  - C2 Beacon (session path)
"""
import math
from collections import Counter, defaultdict

from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.config import THRESHOLDS
from netsentinel.extractor.unsw_feature_builder import (
    build_unsw_features,
    ConnectionTracker,
)
from netsentinel.extractor.dns_feature_builder import build_dns_features


class FlowAnalyzer:
    """Routes flows to models and collects alerts."""
    
    def __init__(self, registry: ModelRegistry, alert_manager: AlertManager):
        self.registry = registry
        self.alert_manager = alert_manager
        self.flows_processed = 0

        # Connection tracker for UNSW-NB15 ct_* features (port scan)
        self._conn_tracker = ConnectionTracker()

        # DDoS evidence: track recent source IPs per destination for entropy
        self._recent_src_ips: dict[str, list[str]] = defaultdict(list)
        _MAX_SRC_IP_WINDOW = 200  # Track last 200 source IPs per target

        # Port scan evidence: track recent dst ports per source IP
        self._recent_dst_ports: dict[str, set[int]] = defaultdict(set)
    
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
        """Run DGA detection + exfiltration detection on a DNS query."""
        domain = event.get("domain", "")
        if not domain:
            return None
        
        source_ip = event.get("source_ip")
        flow_meta = {"domain": domain, "src_ip": source_ip}

        # --- DGA detection ---
        if self.registry.dga:
            result = self.registry.dga.predict(domain)
            
            # Calculate raw entropy to filter out false positives
            import math
            from collections import Counter
            parts = domain.lower().strip().split('.')
            analysis_str = '.'.join(parts[:-1]) if len(parts) > 1 else domain
            freq = Counter(analysis_str)
            total = len(analysis_str)
            entropy = -sum((c/total) * math.log2(c/total) for c in freq.values()) if total > 0 else 0
            
            # Only alert if model says malicious AND entropy is high
            if result["is_malicious"] and result["confidence"] >= THRESHOLDS["dga"] and entropy > 3.0:
                return self.alert_manager.create_alert(
                    result,
                    source_ip=source_ip,
                    flow_meta=flow_meta,
                )

        # --- Exfiltration detection (DNS tunnel) ---
        if self.registry.exfiltration:
            dns_features = build_dns_features(domain)
            if dns_features:
                # Add byte counts if available in the event
                if "features" in event:
                    fwd_bytes = event["features"].get("Fwd Packets Length Total", 0)
                    bwd_bytes = event["features"].get("Bwd Packets Length Total", 0)
                    if fwd_bytes or bwd_bytes:
                        dns_features["total_fwd_bytes"] = fwd_bytes
                        dns_features["total_bwd_bytes"] = bwd_bytes
                
                result = self.registry.exfiltration.predict(dns_features)
                if (result.get("threat") == "Data Exfiltration"
                        and result.get("confidence", 0) >= THRESHOLDS["exfiltration"]):
                    return self.alert_manager.create_alert(
                        result,
                        source_ip=source_ip,
                        flow_meta=flow_meta,
                    )

        return None
    
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
            return self.alert_manager.create_alert(
                result,
                source_ip=event.get("source_ip"),
                dest_ip=event.get("dest_ip"),
                flow_meta=flow_meta,
            )
        return None
    
    def _analyze_flow(self, event: dict) -> dict | None:
        """Run DDoS, ETT, and/or Port Scan detection on a single flow."""
        features = event.get("features", {})
        flow_meta = self._build_flow_meta(event)
        source_ip = event.get("source_ip")
        dest_ip = event.get("dest_ip")
        alert = None
        
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

        # --- DDoS detection ---
        if self.registry.ddos and features:
            result = self.registry.ddos.predict(features)
            if result["is_attack"] and result["confidence"] >= THRESHOLDS["ddos"]:
                # Heuristic guard: real DDoS has high packet/byte rates
                pkt_rate = features.get("Flow Packets/s", 0)
                byte_rate = features.get("Flow Bytes/s", 0)
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
        
        # --- Encrypted traffic detection (only if no DDoS detected) ---
        if alert is None and self.registry.ett and features:
            result = self.registry.ett.predict(features)
            if result["is_vpn"] and result["confidence"] >= THRESHOLDS["encrypted_malware"]:
                alert = self.alert_manager.create_alert(
                    result,
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    flow_meta=flow_meta,
                )

        # --- Port Scan detection (only if no DDoS or ETT alert) ---
        if alert is None and self.registry.port_scan and features:
            unsw_features = build_unsw_features(event, self._conn_tracker)
            if unsw_features:
                # Add scanned ports evidence if available
                if source_ip and source_ip in self._recent_dst_ports:
                    unsw_features["scanned_ports"] = list(self._recent_dst_ports[source_ip])
                    unsw_features["dst_ip"] = dest_ip or "unknown"
                    unsw_features["window_seconds"] = 8
                
                result = self.registry.port_scan.predict(unsw_features)
                if (result.get("threat") == "Port Scan"
                        and result.get("confidence", 0) >= THRESHOLDS["port_scan"]):
                    alert = self.alert_manager.create_alert(
                        result,
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        flow_meta=flow_meta,
                    )
        
        return alert
    
    def get_stats(self) -> dict:
        """Return pipeline statistics."""
        return {
            "flows_processed": self.flows_processed,
            **self.alert_manager.get_stats(),
        }


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
