"""DDoS Detector — XGBoost ONNX Wrapper.

Input: 59 flow-level features (from CIC-DDoS2019 feature set)
Output: {"threat": "DDoS", "confidence": float, "is_attack": bool}

The XGBoost model was trained on CIC-DDoS2019 with 99.97% F1.
It expects exactly the features listed in feature_names.json.
"""
import json
import numpy as np
import onnxruntime as ort

from netsentinel.config import DDOS_MODEL_PATH, DDOS_FEATURES_PATH, DDOS_LABELS_PATH


class DDoSDetector:
    def __init__(self):
        self.session = ort.InferenceSession(
            DDOS_MODEL_PATH,
            providers=['CPUExecutionProvider']
        )
        
        # Load feature names (59 features)
        with open(DDOS_FEATURES_PATH, 'r') as f:
            self.feature_names = json.load(f)
        
        # Load label mapping
        with open(DDOS_LABELS_PATH, 'r') as f:
            self.label_map = json.load(f)
        
        # Get input/output names from ONNX model
        self.input_name = self.session.get_inputs()[0].name
        self.n_features = len(self.feature_names)
        
        print(f"  [OK] DDoS Detector loaded ({self.n_features} features)")
    
    def predict(self, features: dict) -> dict:
        """
        Run DDoS detection on a single flow.
        
        Args:
            features: dict mapping feature name → float value.
                      Missing features are filled with 0.
        
        Returns:
            dict with threat, confidence, is_attack, subtype
        """
        # Build feature vector in correct order
        feature_vec = np.array(
            [features.get(name, 0.0) for name in self.feature_names],
            dtype=np.float32
        ).reshape(1, -1)
        
        # Degenerate-flow guard: reject all-zero vectors before inference.
        # An all-zero feature vector is not a real flow (it means missing data).
        # Without this guard the model can produce false-positive DDoS alerts.
        if not np.any(feature_vec):
            return {
                "threat": "Benign",
                "confidence": 0.0,
                "is_attack": False,
                "subtype": "Benign",
                "model": "ddos_binary_xgboost",
            }

        # Run inference
        results = self.session.run(None, {self.input_name: feature_vec})
        
        # XGBoost ONNX output: [predicted_label, probabilities]
        # IMPORTANT: For this model, label 0 = DDoS, label 1 = Benign
        # probabilities shape: [1, 2] where index 0 = DDoS prob, index 1 = Benign prob
        predicted_label = int(results[0][0])
        
        # Extract DDoS probability (index 0)
        prob_output = results[1]
        if isinstance(prob_output, np.ndarray):
            if prob_output.ndim == 2:
                ddos_confidence = float(prob_output[0, 0])  # Index 0 = DDoS
            else:
                ddos_confidence = float(prob_output[0])
        elif isinstance(prob_output, list):
            p = prob_output[0]
            if isinstance(p, dict):
                ddos_confidence = float(p.get(0, p.get("0", 0.5)))
            else:
                ddos_confidence = float(p)
        else:
            ddos_confidence = 0.5
        
        # Threshold tuning: require 98% confidence to reduce false positives
        # Standard ML practice for production deployment to balance TPR/FPR
        is_attack = predicted_label == 0 and ddos_confidence > 0.98
        
        result = {
            "threat": "DDoS" if is_attack else "Benign",
            "confidence": float(ddos_confidence) if is_attack else float(1 - ddos_confidence),
            "is_attack": is_attack,
            "subtype": self.label_map.get(str(predicted_label), "Unknown") if is_attack else "Benign",
            "model": "ddos_binary_xgboost",
        }
        
        # Add evidence for frontend specialty panel
        if is_attack:
            # Use flow rate features as evidence (entropy would need connection tracker)
            pps = features.get("Flow Packets/s", 0)
            bps = features.get("Flow Bytes/s", 0)
            
            result["evidence"] = {
                "pps": round(float(pps), 2),
                "bps": round(float(bps), 2),
                "attack_type": self.label_map.get(str(predicted_label), "Unknown"),
            }
        
        return result
    
    def predict_batch(self, features_list: list) -> list:
        """Run on multiple flows at once."""
        return [self.predict(f) for f in features_list]
