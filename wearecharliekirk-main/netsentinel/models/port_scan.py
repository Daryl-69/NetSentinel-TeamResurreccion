"""
Port Scan Detection using XGBoost (Expert 5)
Dataset: UNSW-NB15
MITRE ATT&CK: T1046 - Network Service Scanning (Discovery)
"""
import numpy as np
import onnxruntime as ort
import json
from typing import Dict, Any

from netsentinel.config import PORT_SCAN_MODEL_PATH, PORT_SCAN_FEATURES_PATH


class PortScanDetector:
    """
    Detects port scanning behavior using UNSW-NB15 flow features.
    
    Key indicators:
    - High connection rate to multiple ports
    - Low packets per flow (SYN-only scans)
    - Sequential port targeting
    """
    
    def __init__(self):
        """Initialize port scan detector with ONNX model."""
        # Load ONNX model
        self.session = ort.InferenceSession(PORT_SCAN_MODEL_PATH)
        
        # Load feature names
        with open(PORT_SCAN_FEATURES_PATH) as f:
            features = json.load(f)
            # Keep 'id' — the ONNX model was trained with 40 features including id
            self.feature_names = features
        
        self.threshold = 0.85
        
        print(f"[OK] Port Scan XGBoost loaded ({len(self.feature_names)} features)")
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        try:
            X = np.array(
                [features.get(f, 0.0) for f in self.feature_names],
                dtype=np.float32).reshape(1, -1)
            input_name = self.session.get_inputs()[0].name
            outputs    = self.session.run(None, {input_name: X})
            probs      = outputs[1][0]
            conf       = float(probs[1])

            # CIC feature names for heuristic gate
            rate = features.get("Flow Packets/s", features.get("rate", 0))
            pkts = features.get("Total Fwd Packets", features.get("src_pkts", 0))

            is_threat = conf > self.threshold
            if rate > 0 and pkts < 10:
                is_threat = is_threat or (rate > 100 and conf > 0.7)

            result = {
                "threat":     "Port Scan" if is_threat else "Benign",
                "confidence": conf,
                "model":      "port_scan_xgboost",
                }

            if is_threat:
                result["connection_rate"]  = float(rate)
                result["packets_per_flow"] = int(pkts)
                result["scan_indicator"]   = "high_rate_low_packets"
                if "scanned_ports" in features:
                    result["fan_out"] = {
                        "target_ip": features.get("dst_ip", "unknown"),
                        "ports":     sorted(features["scanned_ports"]),
                        "window":    int(features.get("window_seconds", 8)),
                    }
                result["mitre"] = {
                    "tactic":    "Discovery",
                    "technique": "T1046",
                    "name":      "Network Service Scanning",
                }

            return result

        except Exception as e:
            print(f"[!] Port Scan prediction error: {e}")
            return {
                "threat":     "Benign",
                "confidence": 0.0,
                "model":      "port_scan_xgboost",
                "error":      str(e),
                }

    def predict_with_provenance(self, features):
        """Detect port scan and capture provenance for the integrity layer."""
        from netsentinel.integrity.receipt import ProvenanceResult
        from netsentinel.integrity.encoding import confidence_to_ppm

        result = self.predict(features)
        feature_values = [features.get(f, 0.0) for f in self.feature_names]

        prov = ProvenanceResult(
            prediction_class=result.get("threat", "Benign"),
            score_ppm=confidence_to_ppm(result.get("confidence", 0.0)),
            feature_names=list(self.feature_names),
            feature_values=feature_values,
            preprocessor_ref=None,
        )
        return result, prov

