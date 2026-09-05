"""Alert Manager — Creates structured alert JSON from model outputs.

Every alert follows a standardized schema with:
- Unique ID, timestamp, flow identifiers
- Threat classification + confidence
- MITRE ATT&CK mapping
- Severity assignment
- Geo-IP information (fake for demo)
"""
import uuid
import random
from datetime import datetime, timezone

from netsentinel.config import SEVERITY_MAP, MITRE_MAP, FAKE_GEO, TARGET


class AlertManager:
    """Creates and stores alerts from model predictions."""
    
    def __init__(self, max_stored: int = 1000):
        self.alerts = []
        self.max_stored = max_stored
        self.total_count = 0
        self.threat_counts = {}
    
    def create_alert(
        self,
        model_result: dict,
        source_ip: str = None,
        dest_ip: str = None,
        flow_meta: dict = None,
    ) -> dict:
        """
        Create a structured alert from a model prediction.
        
        Args:
            model_result: dict from any model wrapper (has 'threat', 'confidence', etc.)
            source_ip: attacker IP (or random fake)
            dest_ip: target IP (default: our server)
            flow_meta: optional extra flow metadata
        
        Returns:
            Complete alert dict ready for WebSocket broadcast
        """
        threat = model_result.get("threat", "Unknown")
        confidence = model_result.get("confidence", 0.0)
        
        # Skip benign results
        if threat == "Benign":
            return None
        
        # Assign severity based on threat type + confidence
        base_severity = SEVERITY_MAP.get(threat, "MEDIUM")
        if confidence > 0.95:
            severity = "CRITICAL"
        elif confidence > 0.85:
            severity = base_severity
        elif confidence > 0.70:
            severity = "MEDIUM" if base_severity in ("CRITICAL", "HIGH") else "LOW"
        else:
            severity = "LOW"
        
        # Get MITRE mapping
        mitre = MITRE_MAP.get(threat, {"tactic": "Unknown", "technique": "T0000", "name": "Unknown"})
        
        # Geo-IP (pick random fake attacker for demo)
        if source_ip is None:
            attacker = random.choice(list(FAKE_GEO.values()))
            source_ip = attacker["ip"]
            geo = {
                "src_country": attacker["country"],
                "src_city": attacker["city"],
                "src_lat": attacker["lat"],
                "src_lon": attacker["lon"],
                "dst_country": TARGET["country"],
                "dst_city": TARGET["city"],
                "dst_lat": TARGET["lat"],
                "dst_lon": TARGET["lon"],
            }
        else:
            # Try to find matching fake geo
            geo_match = next((g for g in FAKE_GEO.values() if g["ip"] == source_ip), None)
            if geo_match:
                geo = {
                    "src_country": geo_match["country"],
                    "src_city": geo_match["city"],
                    "src_lat": geo_match["lat"],
                    "src_lon": geo_match["lon"],
                    "dst_country": TARGET["country"],
                    "dst_city": TARGET["city"],
                    "dst_lat": TARGET["lat"],
                    "dst_lon": TARGET["lon"],
                }
            else:
                geo = {"src_country": "??", "dst_country": TARGET["country"]}
        
        # Extract 5-tuple flow ID from flow_meta if available
        flow_id = None
        if flow_meta:
            flow_id = {
                "src_ip": flow_meta.get("src_ip", source_ip),
                "src_port": flow_meta.get("src_port", 0),
                "dst_ip": flow_meta.get("dst_ip", dest_ip or TARGET["ip"]),
                "dst_port": flow_meta.get("dst_port", 0),
                "protocol": flow_meta.get("protocol", "TCP"),
            }
        
        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "dest_ip": dest_ip or TARGET["ip"],
            
            # NEW: 5-tuple flow identifier (Problem #5)
            "flow": flow_id,
            
            "threat_class": threat,
            "threat_subtype": model_result.get("subtype", model_result.get("class_name", "")),
            "confidence": round(confidence, 4),
            "severity": severity,
            "model_name": model_result.get("model", "unknown"),
            "evidence": {
                k: v for k, v in model_result.items()
                if k not in ("threat", "confidence", "model", "is_attack", "is_beacon", "is_malicious", "is_vpn")
            },
            "mitre": mitre,
            "geo": geo,
        }
        
        # Store
        self.alerts.append(alert)
        if len(self.alerts) > self.max_stored:
            self.alerts = self.alerts[-self.max_stored:]
        
        self.total_count += 1
        self.threat_counts[threat] = self.threat_counts.get(threat, 0) + 1
        
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
        }

    def reset(self):
        """Reset all counters and stored alerts."""
        self.alerts.clear()
        self.total_count = 0
        self.threat_counts.clear()
