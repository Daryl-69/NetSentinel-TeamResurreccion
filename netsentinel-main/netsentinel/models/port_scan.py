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
        """
        Predict if flow exhibits port scanning behavior.
        
        Args:
            features: Dictionary of flow features
            
        Returns:
            Dictionary with threat, confidence, and evidence
        """
        try:
            # Extract feature vector in correct order
            X = np.array([features.get(f, 0.0) for f in self.feature_names], dtype=np.float32)
            X = X.reshape(1, -1)
            
            # ONNX inference
            input_name = self.session.get_inputs()[0].name
            outputs = self.session.run(None, {input_name: X})
            
            # Get probabilities [benign_prob, portscan_prob]
            probs = outputs[1][0]  # outputs[1] is probabilities
            conf = float(probs[1])  # Port scan probability
            
            is_threat = conf > self.threshold
            
            # Port scan heuristics (additional gating)
            rate = features.get('rate', 0)
            pkts = features.get('src_pkts', 0)
            
            # Require: high rate + low packets (SYN scan pattern)
            if rate > 0 and pkts < 10:
                is_threat = is_threat or (rate > 100 and conf > 0.7)
            
            result = {
                "threat": "Port Scan" if is_threat else "Benign",
                "confidence": conf,
                "model": "port_scan_xgboost",
            }
            
            if is_threat:
                evidence = {
                    "connection_rate": float(rate),
                    "packets_per_flow": int(pkts),
                    "scan_indicator": "high_rate_low_packets"
                }
                
                # Add fan_out if available (passed from analyzer/connection tracker)
                if "scanned_ports" in features:
                    evidence["fan_out"] = {
                        "target_ip": features.get("dst_ip", "unknown"),
                        "ports": sorted(features["scanned_ports"]),
                        "window": int(features.get("window_seconds", 8)),
                    }
                
                result["evidence"] = evidence
                result["mitre"] = {
                    "tactic": "Discovery",
                    "technique": "T1046",
                    "name": "Network Service Scanning"
                }
            
            return result
            
        except Exception as e:
            print(f"[!] Port Scan prediction error: {e}")
            return {
                "threat": "Benign",
                "confidence": 0.0,
                "model": "port_scan_xgboost",
                "error": str(e)
            }
