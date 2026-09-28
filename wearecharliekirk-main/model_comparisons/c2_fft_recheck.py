"""Re-check of the earlier 'FFT alone ranked the beacon 1st of 9' result (c2cmp.py).
Same flow events, same 100-flow sliding windows (step 25), same shipped FFT function.
Reports how many of the beacon's flow gaps are < 5 s, how many windows each session got,
and the beacon's rank by the MAX over windows (what c2cmp.py used) vs the MEDIAN."""
import os, sys, json, gzip, glob, collections
import numpy as np
W = os.path.expanduser("~/mnt/1_sih26#2/wearecharliekirk-main"); sys.path.insert(0, W)
import logging; logging.disable(logging.WARNING)
from netsentinel.models.registry import ModelRegistry
S = os.path.expanduser("~/scratch/cmp")                       # private flow events, never in the repo
truth = [json.loads(l) for l in open(os.path.join(W, "beacon_truth.jsonl")) if l.strip()]
recs = truth[1:]; bips = {r["dest_ip"] for r in recs if r.get("dest_ip")}
t0, t1 = min(r["ts"] for r in recs) - 60, max(r["ts"] for r in recs) + 60
pairs = collections.defaultdict(list)
for fn in sorted(glob.glob(os.path.join(S, "*.jsonl.gz"))):
    for line in gzip.open(fn, "rt"):
        e = json.loads(line); ts = e.get("timestamp")
        if not ts or not e.get("source_ip") or not e.get("dest_ip") or not (t0 <= ts <= t1): continue
        pairs[(e["source_ip"], e["dest_ip"])].append(float(ts))
reg = ModelRegistry(); reg.load_all(); c2 = reg.c2
out = []
for p, ts in pairs.items():
    ts = np.sort(ts); iat = np.diff(ts)
    if len(ts) < 100: continue
    proms = [float(c2._compute_fft_features(np.concatenate([[0.0], np.diff(ts[st:st+100])]).astype(np.float32))[4])
             for st in range(0, len(ts) - 100 + 1, 25)]
    out.append(dict(is_beacon=p[1] in bips, flows=len(ts), share_of_gaps_under_5s=round(float(np.mean(iat < 5.0)), 2),
                    windows_scored=len(proms), prominence_max=round(max(proms), 2), prominence_median=round(float(np.median(proms)), 2)))
out.sort(key=lambda r: -r["prominence_max"])
b = [r for r in out if r["is_beacon"]][0]
rk = lambda key: 1 + sum(1 for r in out if not r["is_beacon"] and r[key] >= b[key])
res = {"sessions": out, "beacon_rank_by_max_over_windows": [rk("prominence_max"), len(out)],
       "beacon_rank_by_median_over_windows": [rk("prominence_median"), len(out)]}
json.dump(res, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2_fft_recheck.json"), "w"), indent=1)
print(res["beacon_rank_by_max_over_windows"], res["beacon_rank_by_median_over_windows"], b)
