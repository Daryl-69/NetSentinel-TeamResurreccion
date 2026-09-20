

import onnxruntime as ort
import numpy as np
from pathlib import Path
import math
from collections import Counter

CHARS = list('abcdefghijklmnopqrstuvwxyz0123456789-.')
CHAR2IDX = {c: i + 2 for i, c in enumerate(CHARS)}
MAX_LEN = 128

def encode(domain):
    domain = domain.lower().strip()[:MAX_LEN]
    ids = [CHAR2IDX.get(c, 1) for c in domain]
    ids += [0] * (MAX_LEN - len(ids))
    return np.array(ids, dtype=np.int64)

def shannon_entropy(s):
    if not s: return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c/total)*math.log2(c/total) for c in counts.values())

def compute_stat_features(domain):
    domain = domain.lower().strip()
    parts = domain.split('.')
    base = parts[-2] if len(parts) >= 2 else domain
    consonants = sum(1 for c in base if c in 'bcdfghjklmnpqrstvwxyz')
    digits = sum(1 for c in domain if c.isdigit())
    bigrams = [base[i:i+2] for i in range(len(base)-1)]
    common = {'th','he','in','er','an','re','on','en','at','es'}
    bigram_score = sum(1 for b in bigrams if b in common) / max(len(bigrams), 1)
    return np.array([[
        shannon_entropy(domain) / 5.0,
        bigram_score,
        min(len(parts) - 1, 6) / 6.0,
        consonants / max(len(base), 1),
        min(len(domain), 253) / 253.0,
        digits / max(len(domain), 1),
        max(len(p) for p in parts) / 63.0,
    ]], dtype=np.float32)

ONNX_PATH = r"C:\Users\gtrip\Downloads\netsentinel_dga_v2_output\dga_cnn_bilstm_v2.onnx"
UMUDGA_ROOT = r"C:\Users\gtrip\Downloads\UMUDGA - University of Murcia Domain Generation Algorithm Dataset\Domain Generation Algorithms"

sess = ort.InferenceSession(ONNX_PATH)
input_names = [i.name for i in sess.get_inputs()]
print(f"v1 inputs: {input_names}\n")

print(f"{'Family':<20} {'Benign%':>8} {'DGA%':>8} {'Tunnel%':>8} {'Caught%':>8}")
print("-" * 60)

family_results = {}
total_b, total_d, total_t = 0, 0, 0

for family_dir in sorted(Path(UMUDGA_ROOT).iterdir()):
    if not family_dir.is_dir(): continue
    domains = []
    for f in family_dir.rglob("*"):
        if f.is_file():
            try:
                lines = f.read_text(errors="ignore").splitlines()
                domains.extend([l.strip().split(',')[0] for l in lines if '.' in l.strip()])
            except: pass
        if len(domains) >= 300: break
    if not domains: continue

    counts = [0, 0, 0]
    for domain in domains[:300]:
        inp = {"domain_chars": encode(domain)[None, :]}
        if "stat_features" in input_names:
            inp["stat_features"] = compute_stat_features(domain)
        logits = sess.run(None, inp)[0][0]
        counts[int(np.argmax(logits))] += 1

    n = min(len(domains), 300)
    b, d, t = counts[0]/n, counts[1]/n, counts[2]/n
    caught = d + t
    family_results[family_dir.name] = caught
    total_b += counts[0]; total_d += counts[1]; total_t += counts[2]
    print(f"  {family_dir.name:<20} {b:>7.1%} {d:>8.1%} {t:>8.1%} {caught:>8.1%}")

total = total_b + total_d + total_t
print("-" * 60)
print(f"  {'TOTAL':<20} {total_b/total:>7.1%} {total_d/total:>8.1%} {total_t/total:>8.1%} {(total_d+total_t)/total:>8.1%}")
print(f"\nv1 Operational catch rate: {(total_d+total_t)/total:.1%}")
print(f"v1 True miss rate:         {total_b/total:.1%}")