import os, sys, json, gzip, glob, collections, math
import numpy as np
W = os.path.expanduser("~/mnt/1_sih26#2/wearecharliekirk-main"); sys.path.insert(0, W)
import logging; logging.disable(logging.WARNING)
from netsentinel.models.registry import ModelRegistry
S = os.path.expanduser("~/scratch/cmp")
truth = [json.loads(l) for l in open(os.path.join(W, "beacon_truth.jsonl")) if l.strip()]
meta = truth[0]; recs = truth[1:]
beacon_ips = {r["dest_ip"] for r in recs if r.get("dest_ip")}
t_start, t_end = min(r["ts"] for r in recs) - 60, max(r["ts"] for r in recs) + 60

pairs = collections.defaultdict(list)
for fn in sorted(glob.glob(os.path.join(S, "*.jsonl.gz"))):
    for line in gzip.open(fn, "rt"):
        e = json.loads(line); f = e.get("features") or {}
        ts = e.get("timestamp")
        if not ts or not e.get("source_ip") or not e.get("dest_ip"): continue
        if not (t_start <= ts <= t_end): continue          # beacon window only
        pairs[(e["source_ip"], e["dest_ip"])].append({
            "timestamp": float(ts),
            "packet_size": f.get("Avg Fwd Segment Size", f.get("Fwd Packet Length Mean", 0)) or 0,
            "bytes": f.get("Fwd Packets Length Total", f.get("Subflow Fwd Bytes", 0)) or 0,
            "direction": 1, "dest_port": e.get("dest_port") or 0, "src_port": e.get("source_port") or 0})

def series(recs):
    recs = sorted(recs, key=lambda r: r["timestamp"]); out = []
    for i, r in enumerate(recs):
        iat = 0.0 if i == 0 else max(r["timestamp"] - recs[i-1]["timestamp"], 0.0)
        out.append({"iat": iat, "packet_size": float(r["packet_size"]), "bytes": float(r["bytes"]),
                    "direction": 1, "dest_port": r["dest_port"], "src_port": r["src_port"], "timestamp": r["timestamp"]})
    return out

def merged_times(recs, gap=5.0):
    ts = sorted(r["timestamp"] for r in recs); out = []
    for t in ts:
        if not out or t - out[-1] >= gap: out.append(t)
    return np.array(out)

def rule_cv(recs):
    t = merged_times(recs)
    if len(t) < 20: return None
    iat = np.diff(t); return float(np.std(iat) / (np.mean(iat) + 1e-9))

def rule_acf(recs, bin_s=5.0):
    t = merged_times(recs)
    if len(t) < 20: return None
    n = int((t[-1] - t[0]) / bin_s) + 1
    x = np.zeros(n); x[((t - t[0]) / bin_s).astype(int)] = 1.0
    x = x - x.mean(); d = float(np.dot(x, x))
    if d == 0: return None
    lo, hi = int(10 / bin_s), min(int(900 / bin_s), n - 1)
    if hi <= lo: return None
    ac = [float(np.dot(x[:-k], x[k:]) / d) for k in range(lo, hi + 1)]
    return max(ac)

reg = ModelRegistry(); reg.load_all(); c2 = reg.c2
rows = []
for pair, recs in pairs.items():
    s = series(recs); n = len(s)
    row = {"is_beacon": pair[1] in beacon_ips, "n_flows": n, "n_conn": int(len(merged_times(recs))),
           "port": collections.Counter(r["dest_port"] for r in recs).most_common(1)[0][0]}
    row["cv"] = rule_cv(recs); row["acf"] = rule_acf(recs)
    if n >= 100:
        best_p, fired, best_prom = 0.0, False, 0.0
        for st in range(0, n - 100 + 1, 25):
            win = s[st:st+100]; win[0] = dict(win[0], iat=0.0)
            r = c2.predict(win)
            best_p = max(best_p, float(r["confidence"])); fired = fired or bool(r["is_beacon"])
            iats = np.array([w["iat"] for w in win], dtype=np.float32)
            best_prom = max(best_prom, float(c2._compute_fft_features(iats)[4]))
        row.update(bilstm_p=best_p, bilstm_fired=fired, fft_prom=best_prom)
    rows.append(row)

def rank(key, higher=True, pool=None):
    pool = [r for r in (pool or rows) if r.get(key) is not None]
    pool.sort(key=lambda r: r[key], reverse=higher)
    br = [i + 1 for i, r in enumerate(pool) if r["is_beacon"]]
    return (min(br) if br else None), len(pool)

print("beacon check-ins logged:", len(recs), "| beacon pairs:", sum(r["is_beacon"] for r in rows),
      "| all pairs:", len(rows))
for r in rows:
    if r["is_beacon"]:
        print("  beacon pair: flows", r["n_flows"], "merged conns", r["n_conn"], "cv", None if r["cv"] is None else round(r["cv"],3),
              "acf", None if r["acf"] is None else round(r["acf"],3), "bilstm_p", r.get("bilstm_p"), "fired", r.get("bilstm_fired"), "fft_prom", r.get("fft_prom"))
big = [r for r in rows if r["n_flows"] >= 100]
print("pairs with >=100 flows (where the shipped model can run):", len(big))
for name, key, hi, pool in [("BiLSTM+FFT (shipped) prob", "bilstm_p", True, big),
                            ("FFT prominence only", "fft_prom", True, big),
                            ("Regularity rule (low CV)", "cv", False, None),
                            ("Autocorrelation rule", "acf", True, None)]:
    k, N = rank(key, hi, pool); print(f"  {name:28s} beacon rank {k} of {N}")
print("  shipped model fired on beacon:", any(r.get("bilstm_fired") for r in rows if r["is_beacon"]),
      "| fired on benign pairs:", sum(1 for r in rows if not r["is_beacon"] and r.get("bilstm_fired")))
top = sorted([r for r in rows if r["cv"] is not None], key=lambda r: r["cv"])[:8]
print("most regular pairs (port, merged conns, cv, beacon?):", [(r["port"], r["n_conn"], round(r["cv"],3), r["is_beacon"]) for r in top])

out = {"window_utc": [t_start, t_end], "checkins_logged": len(truth) - 1, "pairs_total": len(rows),
       "pairs_model_can_score": len(big),
       "model_table": [{k: r.get(k) for k in ("port", "n_flows", "n_conn", "bilstm_p", "bilstm_fired", "fft_prom", "cv", "acf", "is_beacon")}
                       for r in sorted(big, key=lambda r: -(r.get("fft_prom") or 0))],
       "ranks_on_model_pairs": {"bilstm_prob": rank("bilstm_p", True, big), "fft_prominence": rank("fft_prom", True, big),
                                "regularity_cv": rank("cv", False, big), "autocorrelation": rank("acf", True, big)},
       "ranks_on_all_pairs_ge20conns": {"regularity_cv": rank("cv", False), "autocorrelation": rank("acf", True)},
       "bilstm_prob_all_equal_1": all(abs((r.get("bilstm_p") or 0) - 1.0) < 1e-6 for r in big),
       "shipped_fired_on_beacon": any(r.get("bilstm_fired") for r in rows if r["is_beacon"]),
       "shipped_fired_on_benign_pairs": sum(1 for r in rows if not r["is_beacon"] and r.get("bilstm_fired"))}
json.dump(out, open(os.path.join(S, "c2_compare.json"), "w"), indent=1, default=str)
print("saved c2_compare.json")
