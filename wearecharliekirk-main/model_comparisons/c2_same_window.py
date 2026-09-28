"""Head-to-head on the SAME hours: the combined beacon score vs the shipped BiLSTM + FFT model.
Period 1 = the 4-hour beacon window used by c2cmp.py (c2_compare.json).
Period 2 = the 7.4 hours of 22 Sep benign traffic used by fft_benign.py (fft_benign.json).
The combined score, its weights, filters and the 0.80 threshold are unchanged from
c2_beacon_score.py; only the window is set to each period instead of 6-hour blocks."""
import os, json, gzip, glob, collections
HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "c2_beacon_score.py")).read()
exec(src[:src.index("truth = [json.loads")])          # identical score functions, weights, filters
THR = 0.80
S = os.path.expanduser("~/scratch/cmp")                 # private flow events (period bounds only)
truth = [json.loads(l) for l in open(os.path.join(W, "beacon_truth.jsonl")) if l.strip()]
beacon_ips = {r["dest_ip"] for r in truth[1:] if r.get("dest_ip")}
c2c = json.load(open(os.path.join(HERE, "c2_compare.json"))); fb = json.load(open(os.path.join(HERE, "fft_benign.json")))
tmin, tmax = 1e20, 0
for fn in glob.glob(os.path.join(S, "benign", "*.jsonl.gz")):
    for line in gzip.open(fn, "rt"):
        ts = json.loads(line).get("timestamp")
        if ts: tmin, tmax = min(tmin, ts), max(tmax, ts)
periods = {"beacon_window_20_sep": tuple(c2c["window_utc"]), "benign_22_sep": (tmin, tmax)}
data = {k: dict(pairs=collections.defaultdict(list), hours=set(), srcs=collections.defaultdict(set),
                port=collections.defaultdict(collections.Counter)) for k in periods}
for fn in glob.glob(os.path.join(OUT, "*.conns.gz")):
    if os.path.getsize(fn) == 0: continue
    for line in gzip.open(fn, "rt"):
        t, s, d, sp, dp, proto, bf, bb, pk, last = json.loads(line)
        for k, (a, b) in periods.items():
            if a <= t <= b:
                D = data[k]; D["hours"].add(int(t // 3600))
                if proto in (6, 17) and not skip_dst(d, dp):
                    D["pairs"][(s, d)].append((t, bf)); D["srcs"][d].add(s); D["port"][(s, d)][dp] += 1
res = {"what": __doc__.strip(), "threshold": THR}
for k, (a, b) in periods.items():
    D = data[k]; rows = []
    for (s, d), cs in D["pairs"].items():
        m = merge(cs)
        if len(m) < 20 or m[-1][0] - m[0][0] < 1800: continue
        f = features(m, len(D["srcs"][d]), D["hours"])
        f.update(is_beacon=d in beacon_ips, port=D["port"][(s, d)].most_common(1)[0][0]); rows.append(f)
    ben = [r for r in rows if not r["is_beacon"]]; pos = [r for r in rows if r["is_beacon"]]
    out = {"hours": round((b - a) / 3600, 2), "sessions_scored": len(rows),
           "combined_score": {"benign_alerts": sum(r["score"] >= THR for r in ben),
                              "benign_alert_ports": collections.Counter(r["port"] for r in ben if r["score"] >= THR).most_common()}}
    if pos:
        bp = max(pos, key=lambda r: r["score"])
        out["combined_score"].update(beacon_score=round(bp["score"], 3), beacon_caught=bp["score"] >= THR,
                                     beacon_rank=[1 + sum(r["score"] >= bp["score"] for r in ben), len(rows)])
    if k == "beacon_window_20_sep":
        out["shipped_bilstm_fft"] = {"beacon_caught": c2c["shipped_fired_on_beacon"], "benign_alerts": c2c["shipped_fired_on_benign_pairs"],
                                     "sessions_it_can_score": c2c["pairs_model_can_score"], "note": "benign alert was SSDP, port 1900"}
    else:
        out["shipped_bilstm_fft"] = {"benign_alerts": sum(1 for r in fb["rows"] if r["bilstm_fired"]), "sessions_it_can_score": fb["pairs_ge100"],
                                     "alert_ports": [r["port"] for r in fb["rows"] if r["bilstm_fired"]]}
    res[k] = out
    print(k, json.dumps(out))
json.dump(res, open(os.path.join(HERE, "c2_same_window.json"), "w"), indent=1, default=str)
