"""Alert Manager -- builds every alert in the v1 schema.

Every alert, whichever detector raised it, carries (PS 26145 constraint e):
- timestamp / detected_at: when the sensor raised it (UTC)
- event_time and event_window: when the evidence happened on the wire
- flow_id: 5-tuple (or the host / host pair the evidence is about) plus the
  Community ID hash, so the flow can be found in Zeek, Suricata or Wireshark
- threat_class, threat_subtype, ps_category (a-f)
- confidence and confidence_kind (model probability, anomaly score, rule
  score or weighted score -- they are different kinds of number)
- evidence: the detector's supporting evidence, unchanged
- latency_ms: analyzer time and extractor-to-alert time, measured
- MITRE ATT&CK mapping, severity, detector name, receipt reference

See netsentinel/pipeline/alert_schema.py and docs/ALERT_SCHEMA.md.

Nothing is made up. The earlier version filled a missing destination with a
fixed demo address (10.0.0.1) and attached random attacker geolocation from a
demo table; both are gone. Unknown fields stay null.
"""
import time
import uuid
from datetime import datetime, timezone

from netsentinel.config import SEVERITY_MAP, MITRE_MAP, SENSOR_ID
from netsentinel.pipeline.alert_schema import SCHEMA_ID, PS_CATEGORY, community_id, validate_alert

# Keys of a model/detector result that describe the decision itself rather
# than the evidence for it; everything else is copied into "evidence".
_NOT_EVIDENCE = {
    "threat", "confidence", "model", "is_attack", "is_beacon", "is_malicious",
    "is_vpn", "subtype", "threat_type", "severity", "src_ip", "dst_ip",
    "confidence_kind", "detector",
}

# How each detector's confidence number should be read.
_CONFIDENCE_KIND_BY_MODEL = {
    "ddos_binary_xgboost": "model_probability",
    "dga_cnn_bilstm_v2": "model_probability",
    "dga_cnn_bilstm": "model_probability",
    "c2_beacon_bilstm": "model_probability",
    "ett_transformer": "model_probability",
    "exfil_vae": "anomaly_score",
    "portscan_spsd": "model_probability",
}


def _iso(ts):
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _as_port(v):
    try:
        v = int(v)
        return v if 0 <= v <= 65535 else None
    except (TypeError, ValueError):
        return None


def _proto_name(p):
    if p is None:
        return None
    if isinstance(p, str):
        return p.upper()
    return {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMP6"}.get(int(p), str(p))


class AlertManager:
    """Creates and stores alerts from detector results."""

    def __init__(self, max_stored: int = 1000, metrics=None):
        self.alerts = []
        self.max_stored = max_stored
        self.total_count = 0
        self.threat_counts = {}
        self.metrics = metrics
        # Every alert is checked against the v1 schema as it is built; the
        # Overview shows this count (it should stay 0).
        self.schema_violations = 0
        self.last_schema_problems: list = []

    def create_alert(
        self,
        model_result: dict,
        source_ip: str = None,
        dest_ip: str = None,
        flow_meta: dict = None,
        context: dict = None,
    ) -> dict:
        """Build a v1 alert from a detector result.

        Args:
            model_result: dict from a model wrapper or rule detector
                ('threat', 'confidence', 'model', evidence fields...).
            source_ip, dest_ip: the addresses the evidence is about. None
                stays None -- nothing is substituted.
            flow_meta: 5-tuple fields (src_ip, src_port, dst_ip, dst_port,
                protocol) and optionally 'scope'.
            context: timing and provenance from the analyzer:
                event_start / event_end (epoch s, wire time),
                t0_perf (perf_counter at analyzer entry),
                ingest_wall (epoch s when the extractor emitted the event),
                confidence_kind, detector.

        Returns:
            The alert dict, or None for a benign result.
        """
        threat = model_result.get("threat", "Unknown")
        if threat == "Benign":
            return None
        confidence = float(model_result.get("confidence", 0.0) or 0.0)
        confidence = min(1.0, max(0.0, confidence))
        ctx = context or {}
        fm = flow_meta or {}

        # ---- severity (unchanged policy: class default adjusted by confidence)
        base_severity = SEVERITY_MAP.get(threat, "MEDIUM")
        if confidence > 0.95:
            severity = "CRITICAL"
        elif confidence > 0.85:
            severity = base_severity
        elif confidence > 0.70:
            severity = "MEDIUM" if base_severity in ("CRITICAL", "HIGH") else "LOW"
        else:
            severity = "LOW"
        # Uncertain DNS-name detections without strong lexical indicators are
        # left for analyst review (INFO). The earlier rule also required a
        # "byte_ratio" field, which was being fabricated when no byte counts
        # existed; the decision now rests only on measured indicators.
        if confidence < 0.90 and threat in ("DGA", "Data Exfiltration") \
                and model_result.get("model") in ("dga_cnn_bilstm_v2", "dga_cnn_bilstm", "exfil_vae"):
            if threat == "DGA":
                strong = model_result.get("entropy", 0) > 4.0
            else:
                strong = (model_result.get("dns_entropy", 0) > 4.5
                          and model_result.get("subdomain_length", 0) > 30)
            if not strong:
                severity = "INFO"

        mitre = ctx.get("mitre") or MITRE_MAP.get(
            threat, {"tactic": "Unknown", "technique": "T0000", "name": "Unknown"})

        # ---- flow identifier
        src = fm.get("src_ip", source_ip)
        dst = fm.get("dst_ip", dest_ip)
        sport = _as_port(fm.get("src_port"))
        dport = _as_port(fm.get("dst_port"))
        proto = _proto_name(fm.get("protocol"))
        scope = fm.get("scope") or ("flow" if (sport and dport) else ("host_pair" if (src and dst) else "source"))
        cid = community_id(src, dst, sport, dport, proto) if (scope == "flow" and sport and dport) else None
        flow_id = {
            "scope": scope,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "community_id": cid,
        }
        if fm.get("domain"):
            flow_id["domain"] = fm["domain"]

        # ---- times and latency
        now = time.time()
        detected_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        ev_start = ctx.get("event_start")
        ev_end = ctx.get("event_end", ev_start)
        if ev_start is None and ev_end is not None:
            ev_start = ev_end
        event_window = None
        if ev_start is not None and ev_end is not None:
            try:
                s, e = float(ev_start), float(ev_end)
                if e < s:
                    s, e = e, s
                event_window = {"start": _iso(s), "end": _iso(e), "duration_s": round(e - s, 6)}
            except (TypeError, ValueError):
                event_window = None
        pipeline_ms = None
        if ctx.get("t0_perf") is not None:
            pipeline_ms = round((time.perf_counter() - ctx["t0_perf"]) * 1000.0, 3)
        ingest_ms = None
        if ctx.get("ingest_wall") is not None:
            try:
                ingest_ms = round(max(0.0, (now - float(ctx["ingest_wall"])) * 1000.0), 3)
            except (TypeError, ValueError):
                ingest_ms = None

        detector = ctx.get("detector") or model_result.get("detector") or model_result.get("model", "unknown")
        conf_kind = (ctx.get("confidence_kind") or model_result.get("confidence_kind")
                     or _CONFIDENCE_KIND_BY_MODEL.get(detector, "rule_score"))

        evidence = {k: v for k, v in model_result.items() if k not in _NOT_EVIDENCE}

        alert = {
            "schema": SCHEMA_ID,
            "id": str(uuid.uuid4()),
            "timestamp": detected_iso,
            "detected_at": detected_iso,
            "event_time": _iso(ev_end),
            "event_window": event_window,
            "flow_id": flow_id,
            "source_ip": src,
            "dest_ip": dst,
            # Legacy 5-tuple block kept so older consoles keep working.
            "flow": {
                "src_ip": src, "src_port": sport or 0, "dst_ip": dst,
                "dst_port": dport or 0, "protocol": proto,
            },
            "threat_class": threat,
            "threat_subtype": str(model_result.get("subtype", model_result.get("class_name", "")) or ""),
            "ps_category": PS_CATEGORY.get(threat),
            "confidence": round(confidence, 4),
            "confidence_kind": conf_kind,
            "severity": severity,
            "detector": detector,
            "model_name": model_result.get("model", detector),
            "evidence": evidence,
            "mitre": mitre,
            "latency_ms": {"pipeline": pipeline_ms if pipeline_ms is not None else 0.0,
                           "ingest_to_alert": ingest_ms},
            "sensor_id": SENSOR_ID,
            # Integrity layer: receipt envelope digest (set by the sealer)
            "receipt_ref": None,
        }

        problems = validate_alert(alert)
        if problems:
            self.schema_violations += 1
            self.last_schema_problems = problems

        self.alerts.append(alert)
        if len(self.alerts) > self.max_stored:
            self.alerts = self.alerts[-self.max_stored:]
        self.total_count += 1
        self.threat_counts[threat] = self.threat_counts.get(threat, 0) + 1
        if self.metrics is not None:
            self.metrics.alert(threat, ingest_ms)
        return alert

    def get_recent(self, n: int = 50) -> list:
        """Get the N most recent alerts."""
        return list(reversed(self.alerts[-n:]))

    def get_stats(self) -> dict:
        """Get alert statistics for the dashboard."""
        return {
            "total_alerts": self.total_count,
            "threat_distribution": dict(self.threat_counts),
            "recent_count": len(self.alerts),
            "schema_violations": self.schema_violations,
        }

    def reset(self):
        """Reset all counters and stored alerts."""
        self.alerts.clear()
        self.total_count = 0
        self.threat_counts.clear()
        self.schema_violations = 0
        self.last_schema_problems = []
