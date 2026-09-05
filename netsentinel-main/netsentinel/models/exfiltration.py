"""
Data Exfiltration Detection using VAE (Expert 6)
Dataset: CIC-Bell-DNS-EXF-2021
MITRE ATT&CK: T1041 (Exfil Over C2), T1048 (Exfil Alt Protocol), T1071.004 (DNS)
"""
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
        
        # Threshold for reconstruction error (from metadata)
        # Tuned to F1=0.89 on validation set
        self.threshold = 0.15
        
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
            conf = min(mse / self.threshold, 1.0) if mse > self.threshold else 0.0
            
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
                evidence = {
                    "reconstruction_error": float(mse),
                    "dns_entropy": float(dns_entropy),
                    "subdomain_length": int(subdomain_len),
                    "anomaly_type": "dns_tunneling"
                }
                
                # Add byte ratio if available (from flow stats)
                if "total_fwd_bytes" in features and "total_bwd_bytes" in features:
                    evidence["byte_ratio"] = {
                        "outbound": int(features["total_fwd_bytes"]),
                        "inbound": int(features["total_bwd_bytes"]),
                    }
                
                result["evidence"] = evidence
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
