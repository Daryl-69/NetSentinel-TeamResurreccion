"""DGA / DNS Tunnel Detector — CNN-BiLSTM ONNX Wrapper (v2).

Input:  Domain name string (e.g., "xkqw8f3m.evil.com")
Output: {"threat": "DGA"|"DNS Tunnel"|"Benign", "confidence": float, ...}

v2 model (dga_cnn_bilstm_v2.onnx):
  - Two input branches:
      domain_chars  [batch, 128] int64  — character-level encoding
      stat_features [batch, 7]   float32 — domain statistical features
  - Vocab: 0=PAD, 1=UNK, 2–39 = a-z0-9-. (vocab_size=40)
  - Classes: ['benign', 'dga', 'dns_tunnel']
  - Best macro-F1: 0.9787 (family-wise split, 27 DGA families held out)
  - Inference: ~1.85 ms/domain
"""
import math
import numpy as np
import onnxruntime as ort
from collections import Counter

from netsentinel.config import DGA_MODEL_PATH

# ── Vocabulary ──────────────────────────────────────────────────────────────
# 0 = PAD, 1 = UNK, 2–39 = a-z 0-9 - .   (vocab_size = 40, matches training)
CHAR_VOCAB = {c: i + 2 for i, c in enumerate("abcdefghijklmnopqrstuvwxyz0123456789-.")}
MAX_DOMAIN_LEN = 128

# ── Class names (must match training order) ──────────────────────────────────
CLASS_NAMES = ["benign", "dga", "dns_tunnel"]
THREAT_DISPLAY = {"benign": "Benign", "dga": "DGA", "dns_tunnel": "DNS Tunnel"}

# ── English bigram frequencies for bigram score ──────────────────────────────
_ENGLISH_BIGRAM_FREQ = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205, "an": 0.0199,
    "on": 0.0176, "en": 0.0145, "at": 0.014, "es": 0.0132, "ed": 0.0131,
    "or": 0.0128, "ti": 0.0127, "is": 0.0113, "it": 0.0112, "al": 0.0109,
    "ar": 0.0107, "st": 0.0105, "to": 0.0104, "nt": 0.0104, "ng": 0.0095,
    "se": 0.0093, "ha": 0.0093, "ou": 0.0087, "io": 0.0083, "le": 0.0083,
    "nd": 0.0082, "re": 0.0081, "ea": 0.0069, "de": 0.0069, "co": 0.0068,
    "te": 0.0067, "of": 0.0067, "ra": 0.0062, "ri": 0.0062, "ne": 0.0058,
    "me": 0.0057, "sa": 0.0056, "li": 0.0054, "la": 0.0054, "el": 0.0053,
    "ve": 0.0052, "ta": 0.0051, "ce": 0.0049, "si": 0.0048, "ic": 0.0045,
    "no": 0.0044, "ma": 0.0044, "di": 0.0043, "ro": 0.0043, "as": 0.0042,
}
_VOWELS = set("aeiou")


def _encode_domain(domain: str) -> np.ndarray:
    """Encode a domain string to a padded int64 array of length MAX_DOMAIN_LEN.

    Encoding: 0=PAD, 1=UNK for unknown chars, 2-39 for known chars.
    """
    domain = domain.lower().strip()
    encoded = [CHAR_VOCAB.get(c, 1) for c in domain[:MAX_DOMAIN_LEN]]  # 1 = UNK
    encoded += [0] * (MAX_DOMAIN_LEN - len(encoded))                   # 0 = PAD
    return np.array(encoded, dtype=np.int64)


def _compute_stat_features(domain: str) -> np.ndarray:
    """Compute 7 statistical features for the domain (matches training exactly).

    Features: [shannon_entropy/5, bigram_score, subdomain_count/6,
               consonant_ratio, domain_length/253, digit_ratio, max_label_length/63]
    """
    domain_lower = domain.lower().strip()
    parts = domain_lower.split(".")
    analysis_str = ".".join(parts[:-2]) if len(parts) > 2 else parts[0]

    # 1. Shannon entropy (normalised to ~[0,1] by dividing by 5)
    if len(analysis_str) == 0:
        entropy = 0.0
    else:
        freq = Counter(analysis_str)
        total = len(analysis_str)
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())

    # 2. Bigram score (English-likeness)
    bigrams = [analysis_str[i : i + 2] for i in range(len(analysis_str) - 1)]
    if bigrams:
        bg_scores = [_ENGLISH_BIGRAM_FREQ.get(bg, 0.0001) for bg in bigrams]
        bigram_score = sum(math.log(s) for s in bg_scores) / len(bg_scores)
        bigram_score = max(0.0, min(1.0, (bigram_score + 9.0) / 6.0))
    else:
        bigram_score = 0.0

    # 3. Subdomain count (normalised)
    subdomain_count = len(parts) - 2 if len(parts) > 2 else 0
    subdomain_count_norm = min(subdomain_count / 6.0, 1.0)

    # 4. Consonant ratio
    alpha_chars = [c for c in analysis_str if c.isalpha()]
    consonant_ratio = (
        sum(1 for c in alpha_chars if c not in _VOWELS) / len(alpha_chars)
        if alpha_chars
        else 0.0
    )

    # 5. Domain length (normalised)
    domain_length_norm = min(len(domain_lower) / 253.0, 1.0)

    # 6. Digit ratio
    digit_ratio = (
        sum(1 for c in analysis_str if c.isdigit()) / len(analysis_str)
        if analysis_str
        else 0.0
    )

    # 7. Max label length (normalised)
    label_lengths = [len(p) for p in parts[:-2]] if len(parts) > 2 else [len(parts[0])]
    max_label_norm = min(max(label_lengths) / 63.0, 1.0) if label_lengths else 0.0

    return np.array(
        [entropy / 5.0, bigram_score, subdomain_count_norm, consonant_ratio,
         domain_length_norm, digit_ratio, max_label_norm],
        dtype=np.float32,
    )


class DGADetector:
    def __init__(self):
        self.session = ort.InferenceSession(
            DGA_MODEL_PATH,
            providers=["CPUExecutionProvider"],
        )
        inputs = self.session.get_inputs()
        self._char_input_name = inputs[0].name    # "domain_chars"
        self._dual_input = len(inputs) > 1
        if self._dual_input:
            self._stat_input_name = inputs[1].name
            print(f"  [OK] DGA Detector v2 loaded (char[{MAX_DOMAIN_LEN}] + stat[7], vocab={len(CHAR_VOCAB)+2}, 3 classes)")
        else:
            print(f"  [OK] DGA Detector loaded (char[{MAX_DOMAIN_LEN}], vocab={len(CHAR_VOCAB)+2}, 3 classes, macro-F1=0.9787)")

    def predict(self, domain: str) -> dict:
        """Classify a single domain name.

        Args:
            domain: Full domain string (e.g., "google.com" or "xkq8f3.xyz")

        Returns:
            dict with keys: threat, confidence, is_malicious, class_name,
                            domain, model, all_probs
        """
        char_input = _encode_domain(domain).reshape(1, MAX_DOMAIN_LEN)

        if self._dual_input:
            stat_input = _compute_stat_features(domain).reshape(1, 7)
            logits = self.session.run(None, {
                self._char_input_name: char_input,
                self._stat_input_name: stat_input,
            })[0][0]
        else:
            logits = self.session.run(None, {
                self._char_input_name: char_input,
            })[0][0]

        # Softmax (model outputs raw logits)
        exp_l = np.exp(logits - np.max(logits))
        probs = exp_l / exp_l.sum()

        predicted_class = int(np.argmax(probs))
        confidence = float(probs[predicted_class])
        class_name = CLASS_NAMES[predicted_class]

        return {
            "threat": THREAT_DISPLAY[class_name],
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
        """Classify multiple domains. Returns list of predict() dicts."""
        return [self.predict(d) for d in domains]

    def predict_with_provenance(self, domain: str):
        """Classify a domain and capture provenance for the integrity layer."""
        from netsentinel.integrity.receipt import ProvenanceResult
        from netsentinel.integrity.encoding import confidence_to_ppm

        result = self.predict(domain)
        char_encoded = _encode_domain(domain).tolist()

        prov = ProvenanceResult(
            prediction_class=result.get("threat", "Benign"),
            score_ppm=confidence_to_ppm(result.get("confidence", 0.0)),
            feature_names=["domain", "char_encoding"],
            feature_values=[domain, char_encoded],
            preprocessor_ref=None,
        )
        return result, prov


