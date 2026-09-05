"""DNS-Lexical Feature Builder — Computes the 24 features for Exfiltration detection.

The exfil_vae model was trained on CIC-Bell-DNS-EXF-2021 with 24 DNS-lexical
features. These are all per-query string operations on the domain name — no
sliding window or flow accumulation needed.

Feature names match exfil_meta.json exactly.
"""
import math
import string
from collections import Counter
from typing import Optional


# Character sets for ratio features
_VOWELS = set("aeiouAEIOU")
_HEX_CHARS = set("0123456789abcdefABCDEF")
_DIGITS = set(string.digits)
_LOWERCASE = set(string.ascii_lowercase)
_SPECIAL = set(".-_~!@#$%^&*()+=[]{}|;:',<>?/")


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _bigram_entropy(s: str) -> float:
    """Compute Shannon entropy over character bigrams."""
    if len(s) < 2:
        return 0.0
    bigrams = [s[i:i + 2] for i in range(len(s) - 1)]
    freq = Counter(bigrams)
    total = len(bigrams)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _ratio(s: str, char_set: set) -> float:
    """Fraction of characters in s that belong to char_set."""
    if not s:
        return 0.0
    return sum(1 for c in s if c in char_set) / len(s)


def _max_repeat(s: str) -> int:
    """Length of the longest consecutive run of the same character."""
    if not s:
        return 0
    max_run = 1
    current_run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    return max_run


def _longest_token(domain: str) -> int:
    """Length of the longest label (token between dots)."""
    labels = domain.split(".")
    return max((len(label) for label in labels), default=0)


def build_dns_features(domain: str) -> Optional[dict]:
    """Build all 24 DNS-lexical features for the exfil VAE model.

    The features are computed from the full domain string (FQDN).
    The model uses these to detect DNS tunneling — exfiltration encoded
    in anomalous domain-name patterns.

    Args:
        domain: Full domain name string (e.g., "a1b2c3d4e5.evil.example.com")

    Returns:
        Dictionary with the 24 feature names matching exfil_meta.json,
        or None if domain is empty.
    """
    if not domain:
        return None

    # Normalize: lowercase, strip trailing dot
    domain_lower = domain.lower().strip().rstrip(".")
    if not domain_lower:
        return None

    # Split into labels (tokens between dots)
    labels = domain_lower.split(".")
    num_labels = len(labels)

    # The "subdomain" part is everything except the TLD (last label)
    # For "sub.evil.example.com" → subdomain = "sub.evil.example"
    if num_labels > 1:
        subdomain_part = ".".join(labels[:-1])
    else:
        subdomain_part = domain_lower

    # For entropy calculations, use the full domain (minus TLD for dns_* features)
    # CIC-Bell convention: dns_* features are computed on subdomain portion
    analysis_str = subdomain_part if num_labels > 1 else domain_lower

    # Label lengths
    label_lengths = [len(label) for label in labels]

    # --- Compute all 24 features ---

    # dns_bigram_entropy: bigram entropy of the subdomain portion
    dns_bigram_entropy = _bigram_entropy(analysis_str)

    # dns_digit_ratio: fraction of digits in subdomain
    dns_digit_ratio = _ratio(analysis_str, _DIGITS)

    # dns_entropy: Shannon entropy of subdomain
    dns_entropy = _shannon_entropy(analysis_str)

    # dns_hex_ratio: fraction of hex characters (0-9, a-f) in subdomain
    dns_hex_ratio = _ratio(analysis_str, _HEX_CHARS)

    # dns_len: length of subdomain string
    dns_len = len(analysis_str)

    # dns_log_len: log(1 + len)
    dns_log_len = math.log1p(dns_len)

    # dns_longest_token: length of longest label
    dns_longest_token = _longest_token(domain_lower)

    # dns_lower_ratio: fraction of lowercase letters in subdomain
    dns_lower_ratio = _ratio(analysis_str, _LOWERCASE)

    # dns_max_repeat: longest consecutive char run in subdomain
    dns_max_repeat = _max_repeat(analysis_str)

    # dns_norm_entropy: normalized entropy (entropy / log2(unique chars))
    unique_chars = len(set(analysis_str))
    dns_norm_entropy = (
        dns_entropy / math.log2(unique_chars) if unique_chars > 1 else 0.0
    )

    # dns_special_ratio: fraction of special chars (dots, hyphens, underscores)
    dns_special_ratio = _ratio(analysis_str, _SPECIAL)

    # dns_unique_chars: number of unique characters in subdomain
    dns_unique_chars = unique_chars

    # dns_unique_ratio: unique chars / total length
    dns_unique_ratio = unique_chars / max(dns_len, 1)

    # dns_vowel_ratio: fraction of vowels in subdomain
    dns_vowel_ratio = _ratio(analysis_str, _VOWELS)

    # entropy: Shannon entropy of the full domain (including TLD)
    entropy = _shannon_entropy(domain_lower)

    # fqdn_count: number of labels in the full domain
    fqdn_count = num_labels

    # labels_average: average label length
    labels_average = sum(label_lengths) / max(num_labels, 1)

    # labels_max: maximum label length
    labels_max = max(label_lengths) if label_lengths else 0

    # len: total length of the full domain
    full_len = len(domain_lower)

    # lower: count of lowercase chars in full domain
    lower_count = sum(1 for c in domain_lower if c in _LOWERCASE)

    # numeric: count of numeric chars in full domain
    numeric_count = sum(1 for c in domain_lower if c in _DIGITS)

    # special: count of special chars in full domain (dots, hyphens, etc.)
    special_count = sum(1 for c in domain_lower if c in _SPECIAL)

    # subdomain: number of subdomains (labels minus TLD minus SLD)
    # For "a.b.example.com" → 2 subdomains (a, b)
    subdomain = max(num_labels - 2, 0) if num_labels > 2 else 0

    # subdomain_length: total length of subdomain portion
    subdomain_length = len(subdomain_part) if num_labels > 1 else 0

    return {
        "dns_bigram_entropy": dns_bigram_entropy,
        "dns_digit_ratio": dns_digit_ratio,
        "dns_entropy": dns_entropy,
        "dns_hex_ratio": dns_hex_ratio,
        "dns_len": dns_len,
        "dns_log_len": dns_log_len,
        "dns_longest_token": dns_longest_token,
        "dns_lower_ratio": dns_lower_ratio,
        "dns_max_repeat": dns_max_repeat,
        "dns_norm_entropy": dns_norm_entropy,
        "dns_special_ratio": dns_special_ratio,
        "dns_unique_chars": dns_unique_chars,
        "dns_unique_ratio": dns_unique_ratio,
        "dns_vowel_ratio": dns_vowel_ratio,
        "entropy": entropy,
        "fqdn_count": fqdn_count,
        "labels_average": labels_average,
        "labels_max": labels_max,
        "len": full_len,
        "lower": lower_count,
        "numeric": numeric_count,
        "special": special_count,
        "subdomain": subdomain,
        "subdomain_length": subdomain_length,
    }
