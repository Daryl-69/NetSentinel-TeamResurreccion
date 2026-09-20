"""
Data Exfiltration Detection using VAE (Expert 6)
Dataset: CIC-Bell-DNS-EXF-2021
MITRE ATT&CK: T1041 (Exfil Over C2), T1048 (Exfil Alt Protocol), T1071.004 (DNS)
"""
import math
import numpy as np
import onnxruntime as ort
import joblib
import json
from typing import Dict, Any

from netsentinel.config import EXFIL_MODEL_PATH, EXFIL_SCALER_PATH, EXFIL_META_PATH


class ExfiltrationDetector:
    """
    Detects data exfiltration via DNS tunneling using VAE reconstruction error.
    
    Key indicators:
    - Anomalous DNS query patterns
    - High entropy in domain names
    - Unusual subdomain lengths
    - High volume of DNS queries
    """
    
    def __init__(self):
        """Initialize exfiltration detector with VAE model and scaler."""
        # Load metadata (contains feature names)
        with open(EXFIL_META_PATH) as f:
            self.metadata = json.load(f)
        
        self.feature_names = self.metadata['features']
        
        # Load ONNX model
        self.session = ort.InferenceSession(EXFIL_MODEL_PATH)
        
        # Load scaler (CRITICAL: must match training scikit-learn version)
        self.scaler = joblib.load(EXFIL_SCALER_PATH)
        
        # Threshold for reconstruction error
        # Empirically tuned: normal DNS MSE < 0.45, tunnel DNS MSE > 0.99
        self.threshold = 0.70
        
        print(f"[OK] Exfiltration VAE loaded ({len(self.feature_names)} features)")
    
    @property
    def reconstruction_threshold(self) -> float:
        """Alias for threshold (backwards-compat with test suite)."""
        return self.threshold

    def set_threshold(self, value: float):
        """Adjust the reconstruction-error threshold at runtime."""
        self.threshold = float(value)
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict if DNS traffic indicates data exfiltration.
        
        Args:
            features: Dictionary of DNS/flow features
            
        Returns:
            Dictionary with threat, confidence, and evidence
        """
        try:
            # Extract feature vector in correct order
            X = np.array([features.get(f, 0.0) for f in self.feature_names], dtype=np.float32)
            X = X.reshape(1, -1)
            
            # Scale features (MUST use same scaler as training)
            X_scaled = self.scaler.transform(X).astype(np.float32)
            
            # VAE inference: encoder → latent → decoder
            input_name = self.session.get_inputs()[0].name
            outputs = self.session.run(None, {input_name: X_scaled})
            reconstructed = outputs[0]
            
            # Reconstruction error (MSE)
            mse = float(np.mean((X_scaled - reconstructed) ** 2))
            
            # Normalize confidence: mse > threshold = anomaly
            # Confidence is how much the MSE exceeds threshold
            # Confidence must vary with HOW FAR past the threshold the
            # reconstruction error is. The previous form was
            #     min(mse / threshold, 1.0) if mse > threshold else 0.0
            # and whenever mse > threshold, mse/threshold is by definition > 1,
            # so it clamped to exactly 1.0 every single time -- the score was
            # binary (0.0 or 1.0), never graded. Every detection therefore
            # reported 100% confidence and was escalated to CRITICAL.
            # This is a bounded, strictly monotone map: 0 at the threshold,
            # 0.63 at 2x, 0.95 at 4x, asymptotic to 1 but never equal to it.
            if mse > self.threshold:
                excess = (mse - self.threshold) / self.threshold
                conf = 1.0 - math.exp(-excess)
            else:
                conf = 0.0
            
            is_exfil = mse > self.threshold
            
            # Additional heuristics from DNS features
            dns_entropy = features.get('dns_entropy', 0)
            subdomain_len = features.get('subdomain_length', 0)
            
            # High entropy + long subdomains = likely tunneling
            if dns_entropy > 4.0 and subdomain_len > 30:
                is_exfil = True
                conf = max(conf, 0.75)
            
            result = {
                "threat": "Data Exfiltration" if is_exfil else "Benign",
                "confidence": conf,
                "model": "exfil_vae",
            }
            
            if is_exfil:
                # Put evidence fields at root level - alert_manager will copy to evidence{}
                result["reconstruction_error"] = float(mse)
                result["dns_entropy"] = float(dns_entropy)
                result["subdomain_length"] = int(subdomain_len)
                result["anomaly_type"] = "dns_tunneling"
                
                # Add byte ratio if available (from flow stats)
                if "total_fwd_bytes" in features and "total_bwd_bytes" in features:
                    result["byte_ratio"] = {
                        "outbound": int(features["total_fwd_bytes"]),
                        "inbound": int(features["total_bwd_bytes"]),
                    }
                
                result["mitre"] = {
                    "tactic": "Exfiltration",
                    "technique": "T1048",
                    "name": "Exfiltration Over Alternative Protocol (DNS)"
                }
            
            return result
            
        except Exception as e:
            print(f"[!] Exfiltration prediction error: {e}")
            return {
                "threat": "Benign",
                "confidence": 0.0,
                "model": "exfil_vae",
                "error": str(e)
            }

    def predict_with_provenance(self, features):
        """Detect exfiltration and capture provenance for the integrity layer."""
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

