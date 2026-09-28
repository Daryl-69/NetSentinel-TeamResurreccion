"""Alert schema v1 -- the one record format every detector emits.

PS 26145 constraint (e): "standardized alert schema (timestamp, flow
identifier, threat class, confidence, supporting evidence)". Every alert the
sensor raises, whatever produced it (an ONNX model, the port-scan tree or one
of the rule-based detectors), is built by ``AlertManager.create_alert`` into
the shape described by ``ALERT_SCHEMA`` below. ``docs/ALERT_SCHEMA.md``
explains each field; ``docs/alert_schema_v1.json`` is this dict dumped to a
file so tools outside Python can validate against it.

Nothing in an alert is invented. Fields the sensor does not know are null
(e.g. ``dest_ip`` of a DNS alert whose resolver was not seen) -- they are
never filled with a placeholder address or a made-up location.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct
from typing import Any

SCHEMA_ID = "netsentinel.alert/v1"

# PS 26145 threat families (a-f) each threat class belongs to.
PS_CATEGORY = {
    "DDoS": "a",
    "C2 Beacon": "b",
    "DGA": "c",
    "DNS Tunnel": "c",
    "Encrypted Malware": "d",
    "Port Scan": "e",
    "Data Exfiltration": "f",
}

PS_CATEGORY_LABEL = {
    "a": "DDoS (SYN flood, UDP reflection/amplification, spoofed sources)",
    "b": "C2 beaconing",
    "c": "DGA and DNS tunnelling",
    "d": "Malware in encrypted sessions",
    "e": "Reconnaissance and port scans",
    "f": "Data exfiltration",
}

# What the "confidence" number means for a given detector. A model
# probability, an anomaly score and a rule score are all in [0, 1] but they
# are not the same kind of number; the alert says which one it carries.
CONFIDENCE_KINDS = ("model_probability", "anomaly_score", "rule_score", "weighted_score")

_ISO = {"type": "string", "format": "date-time"}
_IP_OR_NULL = {"type": ["string", "null"]}

ALERT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://netsentinel.local/schemas/alert/v1.json",
    "title": "NetSentinel alert (v1)",
    "type": "object",
    "required": [
        "schema", "id", "timestamp", "event_time", "flow_id", "source_ip",
        "dest_ip", "threat_class", "confidence", "confidence_kind",
        "severity", "detector", "evidence", "mitre", "latency_ms",
    ],
    "properties": {
        "schema": {"const": SCHEMA_ID},
        "id": {"type": "string", "minLength": 8},
        "timestamp": {**_ISO, "description": "When the sensor raised the alert (UTC)."},
        "detected_at": {**_ISO, "description": "Same instant as timestamp; explicit name."},
        "event_time": {
            "type": ["string", "null"], "format": "date-time",
            "description": "Wire time of the last packet or event in the evidence (UTC). "
                           "Null only when the source carried no time at all.",
        },
        "event_window": {
            "type": ["object", "null"],
            "properties": {
                "start": _ISO, "end": _ISO,
                "duration_s": {"type": "number", "minimum": 0},
            },
            "required": ["start", "end", "duration_s"],
        },
        "flow_id": {
            "type": "object",
            "required": ["scope", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "community_id"],
            "properties": {
                "scope": {"enum": ["flow", "host_pair", "source", "destination", "dns_query"]},
                "src_ip": _IP_OR_NULL,
                "dst_ip": _IP_OR_NULL,
                "src_port": {"type": ["integer", "null"], "minimum": 0, "maximum": 65535},
                "dst_port": {"type": ["integer", "null"], "minimum": 0, "maximum": 65535},
                "protocol": {"type": ["string", "null"]},
                "community_id": {"type": ["string", "null"], "pattern": "^1:[A-Za-z0-9+/=]{28}$"},
            },
        },
        "source_ip": _IP_OR_NULL,
        "dest_ip": _IP_OR_NULL,
        "flow": {"type": ["object", "null"], "description": "Legacy 5-tuple kept for older consoles."},
        "threat_class": {"type": "string", "minLength": 1},
        "threat_subtype": {"type": "string"},
        "ps_category": {"enum": ["a", "b", "c", "d", "e", "f", None]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "confidence_kind": {"enum": list(CONFIDENCE_KINDS)},
        "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "detector": {"type": "string", "minLength": 1},
        "model_name": {"type": "string"},
        "evidence": {"type": "object"},
        "mitre": {
            "type": "object",
            "required": ["tactic", "technique", "name"],
            "properties": {
                "tactic": {"type": "string"},
                "technique": {"type": "string"},
                "name": {"type": "string"},
            },
        },
        "latency_ms": {
            "type": "object",
            "required": ["pipeline"],
            "properties": {
                "pipeline": {"type": "number", "minimum": 0,
                             "description": "Analyzer entry to alert creation, wall clock."},
                "ingest_to_alert": {"type": ["number", "null"], "minimum": 0,
                                    "description": "Extractor emitted the event to alert creation, wall clock."},
            },
        },
        "sensor_id": {"type": ["string", "null"]},
        "receipt_ref": {"type": ["string", "null"]},
    },
}


def validate_alert(alert: dict) -> list[str]:
    """Light structural check of an alert against ALERT_SCHEMA.

    Runtime use only (no jsonschema dependency on the sensor). The test
    suite validates the same alerts with the full JSON Schema.
    Returns a list of problems; empty means the alert conforms.
    """
    problems = []
    if not isinstance(alert, dict):
        return ["alert is not an object"]
    for key in ALERT_SCHEMA["required"]:
        if key not in alert:
            problems.append(f"missing {key}")
    if alert.get("schema") != SCHEMA_ID:
        problems.append("schema id mismatch")
    conf = alert.get("confidence")
    if not isinstance(conf, (int, float)) or not 0.0 <= float(conf) <= 1.0:
        problems.append("confidence not in [0, 1]")
    if alert.get("confidence_kind") not in CONFIDENCE_KINDS:
        problems.append("unknown confidence_kind")
    fid = alert.get("flow_id") or {}
    for key in ALERT_SCHEMA["properties"]["flow_id"]["required"]:
        if key not in fid:
            problems.append(f"flow_id.{key} missing")
    if not isinstance(alert.get("evidence"), dict):
        problems.append("evidence is not an object")
    return problems


# ---------------------------------------------------------------------------
# Community ID v1 (https://github.com/corelight/community-id-spec)
# ---------------------------------------------------------------------------
_PROTO_NUM = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMP6": 58, "SCTP": 132}


def community_id(src_ip: Any, dst_ip: Any, src_port: Any, dst_port: Any,
                 protocol: Any, seed: int = 0) -> str | None:
    """Community ID v1 flow hash for a TCP/UDP 5-tuple, or None.

    The same flow gets the same ID in Zeek, Suricata, Wireshark and here,
    which is what lets an analyst pivot from a NetSentinel alert into other
    tools. Returns None when the tuple is incomplete or not TCP/UDP.
    """
    try:
        proto = int(protocol) if not isinstance(protocol, str) else _PROTO_NUM.get(protocol.upper())
        if proto not in (6, 17, 132):
            return None
        a = ipaddress.ip_address(str(src_ip))
        b = ipaddress.ip_address(str(dst_ip))
        if a.version != b.version:
            return None
        sp, dp = int(src_port), int(dst_port)
        if not (0 <= sp <= 65535 and 0 <= dp <= 65535):
            return None
    except (TypeError, ValueError):
        return None
    ab, bb = a.packed, b.packed
    # Order the endpoints so both directions of a flow hash the same.
    if (ab, sp) > (bb, dp):
        ab, bb, sp, dp = bb, ab, dp, sp
    data = struct.pack("!H", seed) + ab + bb + struct.pack("!BB", proto, 0) + struct.pack("!HH", sp, dp)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode("ascii")
