import os, sys, json, gzip, glob, collections
import numpy as np
W = os.path.expanduser("~/mnt/1_sih26#2/wearecharliekirk-main"); sys.path.insert(0, W)
import logging; logging.disable(logging.WARNING)
from netsentinel.models.registry import ModelRegistry
S = os.path.expanduser("~/scratch/cmp/benign")
KNOWN_PERIODIC = {53, 123, 1900, 5353, 5355, 137, 138, 67, 68}
pairs = collections.defaultdict(list); tmin, tmax = 1e20, 0
for fn in sorted(glob.glob(os.path.join(S, "*.jsonl.gz"))):
    for line in gzip.open(fn, "rt"):
        e = json.loads(line); f = e.get("features") or {}; ts = e.get("timestamp")
        if not ts or not e.get("source_ip") or not e.get("dest_ip"): continue
        tmin, tmax = min(tmin, ts), max(tmax, ts)
        pairs[(e["source_ip"], e["dest_ip"])].append({"timestamp": float(ts),
            "packet_size": float(f.get("Avg Fwd Segment Size", f.get("Fwd Packet Length Mean", 0)) or 0),
            "bytes": float(f.get("Fwd Packets Length Total", f.get("Subflow Fwd Bytes", 0)) or 0),
            "dest_port": e.get("dest_port") or 0, "src_port": e.get("source_port") or 0})
reg = ModelRegistry(); reg.load_all(); c2 = reg.c2
rows = []
for pair, recs in pairs.items():
    if len(recs) < 100: continue
    recs.sort(key=lambda r: r["timestamp"]); s = []
    for i, r in enumerate(recs):
        s.append({"iat": 0.0 if i == 0 else max(r["timestamp"] - recs[i-1]["timestamp"], 0.0), "packet_size": r["packet_size"],
                  "bytes": r["bytes"], "direction": 1, "dest_port": r["dest_port"], "src_port": r["src_port"]})
    best_prom, fired = 0.0, False
    for st in range(0, len(s) - 100 + 1, 25):
        win = s[st:st+100]; win[0] = dict(win[0], iat=0.0)
        iats = np.array([w["iat"] for w in win], dtype=np.float32)
        best_prom = max(best_prom, float(c2._compute_fft_features(iats)[4]))
        fired = fired or bool(c2.predict(win)["is_beacon"])
    port = collections.Counter(r["dest_port"] for r in recs).most_common(1)[0][0]
    rows.append({"port": port, "flows": len(recs), "fft_prom": best_prom, "bilstm_fired": fired})
hours = (tmax - tmin) / 3600
print(f"benign window {hours:.1f} h | host pairs {len(pairs)} | pairs with >=100 flows: {len(rows)}")
for thr in (3.0, 5.0, 5.5, 5.76):
    allb = [r for r in rows if r["fft_prom"] >= thr]; filt = [r for r in allb if r["port"] not in KNOWN_PERIODIC]
    print(f"  FFT prominence >= {thr}: {len(allb)} benign sessions ({len(filt)} after known-service filter)")
print("  shipped BiLSTM model fired on benign sessions:", sum(r["bilstm_fired"] for r in rows))
top = sorted(rows, key=lambda r: -r["fft_prom"])[:10]
print("  top benign sessions (port, flows, fft_prom):", [(r["port"], r["flows"], round(r["fft_prom"], 2)) for r in top])
json.dump({"hours": hours, "pairs": len(pairs), "pairs_ge100": len(rows), "rows": rows}, open(os.path.expanduser("~/scratch/cmp/fft_benign.json"), "w"))
