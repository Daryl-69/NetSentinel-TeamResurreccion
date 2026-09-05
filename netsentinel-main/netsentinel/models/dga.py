"""DGA / DNS Tunnel Detector — CNN-BiLSTM ONNX Wrapper.

Input: Domain name string (e.g., "xkqw8f3m.evil.com")
Output: {"threat": "DGA"|"DNS Tunnel"|"Benign", "confidence": float}

The model has two input branches:
  - char_input: [1, 253] int64 — character-level encoded domain
  - stat_input: [1, 7] float32 — 7 statistical features
"""
import math
import numpy as np
import onnxruntime as ort
from collections import Counter

from netsentinel.config import DGA_MODEL_PATH

# Character encoding (same as training)
CHAR_VOCAB = {c: i + 1 for i, c in enumerate("abcdefghijklmnopqrstuvwxyz0123456789-.")}
MAX_DOMAIN_LEN = 128

# English bigram frequencies for the bigram score feature
ENGLISH_BIGRAM_FREQ = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205,
    "an": 0.0199, "on": 0.0176, "en": 0.0145, "at": 0.014,
    "es": 0.0132, "ed": 0.0131, "or": 0.0128, "ti": 0.0127,
    "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
    "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095,
    "se": 0.0093, "ha": 0.0093, "ou": 0.0087, "io": 0.0083,
    "le": 0.0083, "nd": 0.0082, "re": 0.0081, "ea": 0.0069,
    "de": 0.0069, "co": 0.0068, "te": 0.0067, "of": 0.0067,
}
VOWELS = set('aeiou')

# Class names (must match training)
CLASS_NAMES = ["benign", "dga", "dns_tunnel"]


def _encode_domain(domain: str) -> np.ndarray:
    """Encode domain to int array [253]."""
    domain = domain.lower().strip()
    encoded = [CHAR_VOCAB.get(c, 0) for c in domain[:MAX_DOMAIN_LEN]]
    # Pad to MAX_DOMAIN_LEN
    encoded += [0] * (MAX_DOMAIN_LEN - len(encoded))
    return np.array(encoded, dtype=np.int64)


def _compute_stat_features(domain: str) -> np.ndarray:
    """Compute 7 statistical features for a domain (matches training code)."""
    domain_lower = domain.lower().strip()
    parts = domain_lower.split('.')
    analysis_str = '.'.join(parts[:-2]) if len(parts) > 2 else parts[0]
    
    # 1. Shannon entropy
    if len(analysis_str) == 0:
        entropy = 0.0
    else:
        freq = Counter(analysis_str)
        total = len(analysis_str)
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
    
    # 2. Bigram score
    bigrams = [analysis_str[i:i+2] for i in range(len(analysis_str) - 1)]
    if bigrams:
        bg_scores = [ENGLISH_BIGRAM_FREQ.get(bg, 0.0001) for bg in bigrams]
        bigram_score = sum(math.log(s) for s in bg_scores) / len(bg_scores)
        bigram_score = max(0.0, min(1.0, (bigram_score + 9.0) / 6.0))
    else:
        bigram_score = 0.0
    
    # 3. Subdomain count
    subdomain_count = len(parts) - 2 if len(parts) > 2 else 0
    subdomain_count_norm = min(subdomain_count / 6.0, 1.0)
    
    # 4. Consonant ratio
    alpha_chars = [c for c in analysis_str if c.isalpha()]
    consonant_ratio = sum(1 for c in alpha_chars if c not in VOWELS) / len(alpha_chars) if alpha_chars else 0.0
    
    # 5. Domain length
    domain_length_norm = min(len(domain_lower) / 253.0, 1.0)
    
    # 6. Digit ratio
    digit_ratio = sum(1 for c in analysis_str if c.isdigit()) / len(analysis_str) if analysis_str else 0.0
    
    # 7. Max label length
    label_lengths = [len(p) for p in parts[:-2]] if len(parts) > 2 else [len(parts[0])]
    max_label_norm = min(max(label_lengths) / 63.0, 1.0) if label_lengths else 0.0
    
    return np.array([
        entropy / 5.0, bigram_score, subdomain_count_norm, consonant_ratio,
        domain_length_norm, digit_ratio, max_label_norm
    ], dtype=np.float32)


class DGADetector:
    def __init__(self):
        self.session = ort.InferenceSession(
            DGA_MODEL_PATH,
            providers=['CPUExecutionProvider']
        )
        
        self.input_names = [inp.name for inp in self.session.get_inputs()]
        print(f"  [OK] DGA Detector loaded (char[253] + stat[7], 3 classes)")
    
    def predict(self, domain: str) -> dict:
        """
        Classify a domain name.
        
        Args:
            domain: Full domain string (e.g., "google.com" or "xkq8f3.xyz")
        
        Returns:
            dict with threat, confidence, domain, class_name
        """
        # Encode
        char_input = _encode_domain(domain).reshape(1, MAX_DOMAIN_LEN)
        stat_input = _compute_stat_features(domain).reshape(1, 7)
        
        # Run inference
        feed = {
            self.input_names[0]: char_input,
            self.input_names[1]: stat_input,
        }
        results = self.session.run(None, feed)
        
        # Output: softmax probabilities [1, 3]
        probs = results[0][0]
        
        # Apply softmax if not already applied
        if probs.min() < 0 or probs.sum() > 1.5:
            exp_probs = np.exp(probs - np.max(probs))
            probs = exp_probs / exp_probs.sum()
        
        predicted_class = int(np.argmax(probs))
        confidence = float(probs[predicted_class])
        class_name = CLASS_NAMES[predicted_class]
        
        # Map to threat name
        threat_map = {"benign": "Benign", "dga": "DGA", "dns_tunnel": "DNS Tunnel"}
        
        return {
            "threat": threat_map.get(class_name, "Unknown"),
            "confidence": confidence,
            "is_malicious": predicted_class != 0,
            "class_name": class_name,
            "domain": domain,
            "model": "dga_cnn_bilstm_v2",
            "all_probs": {
                "benign": float(probs[0]),
                "dga": float(probs[1]),
                "dns_tunnel": float(probs[2]),
            },
        }
    
    def predict_batch(self, domains: list) -> list:
        """Classify multiple domains."""
        return [self.predict(d) for d in domains]
