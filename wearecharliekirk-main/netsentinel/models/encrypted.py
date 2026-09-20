"""Encrypted Traffic Transformer — FT-Transformer ONNX Wrapper.

Input: 29 flow features (from consolidated_traffic_data.csv feature set)
Output: {"threat": "VPN Traffic"|"Benign", "confidence": float, "app_class": str}

Uses RobustScaler parameters saved during training (center/scale).
"""
import json
import numpy as np
import onnxruntime as ort

from netsentinel.config import ETT_MODEL_PATH, ETT_SCALER_PATH, ETT_CLASSES_PATH


class EncryptedTrafficDetector:
    def __init__(self):
        self.session = ort.InferenceSession(
            ETT_MODEL_PATH,
            providers=['CPUExecutionProvider']
        )
        
        # Load scaler (RobustScaler center and scale)
        with open(ETT_SCALER_PATH, 'r') as f:
            scaler_data = json.load(f)
        self.scaler_center = np.array(scaler_data['center'], dtype=np.float32)
        self.scaler_scale = np.array(scaler_data['scale'], dtype=np.float32)
        self.feature_names = scaler_data.get('feature_names', [])
        
        # Prevent division by zero
        self.scaler_scale[self.scaler_scale == 0] = 1.0
        
        # Load class mapping
        with open(ETT_CLASSES_PATH, 'r') as f:
            self.class_map = json.load(f)
        
        self.input_name = self.session.get_inputs()[0].name
        self.n_features = len(self.scaler_center)
        
        print(f"  [OK] Encrypted Traffic Detector loaded ({self.n_features} features, {len(self.class_map)} classes)")
    
    def _scale(self, features: np.ndarray) -> np.ndarray:
        """Apply RobustScaler transform: (X - center) / scale."""
        return (features - self.scaler_center) / self.scaler_scale
    
    def predict(self, features: dict) -> dict:
        """
        Classify encrypted traffic flow.
        
        Args:
            features: dict mapping feature name → float value.
                      Must include the 29 features from training.
        
        Returns:
            dict with threat, confidence, app_class, is_vpn
        """
        # Build feature vector in training order
        feature_vec = np.array(
            [features.get(name, 0.0) for name in self.feature_names],
            dtype=np.float32
        ).reshape(1, -1)
        
        # Scale
        feature_vec = self._scale(feature_vec)
        
        # Run inference
        results = self.session.run(None, {self.input_name: feature_vec})
        logits = results[0][0]
        
        # Softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()
        
        predicted_class = int(np.argmax(probs))
        confidence = float(probs[predicted_class])
        class_name = self.class_map.get(str(predicted_class), "Unknown")
        
        # Determine if it's VPN traffic
        is_vpn = class_name.startswith("VPN-")
        
        result = {
            "threat": "VPN Traffic" if is_vpn else "Benign",
            "confidence": confidence,
            "is_vpn": is_vpn,
            "app_class": class_name,
            "model": "encrypted_traffic_transformer",
        }
        
        # Add JA4 fingerprint if available (from TLS extraction)
        # Put at root level - alert_manager copies to evidence{}
        if is_vpn or confidence > 0.7:
            if "ja4" in features:
                result["ja4"] = features["ja4"]
                
            if "ja4_rarity" in features:
                result["ja4_rarity"] = round(float(features["ja4_rarity"]), 2)
        
        return result
    
    def predict_batch(self, features_list: list) -> list:
        """Classify multiple flows."""
        return [self.predict(f) for f in features_list]

    def predict_with_provenance(self, features: dict):
        """Classify encrypted traffic and capture provenance."""
        from netsentinel.integrity.receipt import ProvenanceResult
        from netsentinel.integrity.encoding import confidence_to_ppm

        result = self.predict(features)
        feature_values = [features.get(name, 0.0) for name in self.feature_names]

        prov = ProvenanceResult(
            prediction_class=result.get("threat", "Benign"),
            score_ppm=confidence_to_ppm(result.get("confidence", 0.0)),
            feature_names=list(self.feature_names),
            feature_values=feature_values,
            preprocessor_ref=None,
        )
        return result, prov

