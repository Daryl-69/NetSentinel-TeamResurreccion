"""Combined beacon score (C2 v2 prototype) — evaluation on every capture.

Score per (source, destination) pair per 6-hour window, from connection starts:
  T  timing regularity   1 - min(1, MAD(interval)/median(interval))
  F  FFT periodicity     min(1, peak_prominence/8)  (same formula as the shipped model)
  S  size regularity     1 - min(1, MAD(bytes)/median(bytes))
  R  destination rarity  1 / number of machines talking to that destination
  C  persistence         share of captured hours in the window with a check-in
  score = 0.30 T + 0.20 F + 0.20 S + 0.15 R + 0.15 C      (weights fixed before any scoring)
Known periodic services (DNS, NTP, SSDP, mDNS, LLMNR, NetBIOS, DHCP) and multicast /
link-local / broadcast destinations are dropped first. A pair needs >= 20 check-ins
(connection starts merged when < 5 s apart) spanning >= 30 minutes."""
import os, sys, gzip, json, glob, ipaddress, collections, random
import numpy as np
W = os.path.expanduser("~/mnt/1_sih26#2/wearecharliekirk-main")
OUT = os.path.expanduser("~/scratch/conns/out")
WEIGHTS = dict(T=0.30, F=0.20, S=0.20, R=0.15, C=0.15)
KNOWN = {53, 123, 1900, 5353, 5355, 137, 138, 67, 68, 546, 547}
WIN = 6 * 3600

def fft_prom(iats):
    iats = np.asarray(iats, dtype=np.float64)
    if len(iats) < 4: return 0.0
    m = np.abs(np.fft.rfft(iats))[1:]
    if len(m) == 0 or m.sum() == 0: return 0.0
    return float((m.max() - np.median(m)) / (np.std(m) + 1e-9))

def mad_ratio(x):
    x = np.asarray(x, dtype=np.float64); med = np.median(x)
    return 1.0 if med <= 0 else float(np.median(np.abs(x - med)) / med)

def skip_dst(ip, dport):
    if dport in KNOWN: return True
    a = ipaddress.ip_address(ip)
    return a.is_multicast or a.is_link_local or ip in ("255.255.255.255",) or a.is_unspecified

def merge(conns, gap=5.0):
    conns = sorted(conns); out = []
    for t, b in conns:
        if out and t - out[-1][0] < gap: out[-1][1] += b
        else: out.append([t, b])
    return out

def features(merged, n_src, cap_hours):
    t = np.array([m[0] for m in merged]); b = np.array([m[1] for m in merged]); iat = np.diff(t)
    T = 1 - min(1.0, mad_ratio(iat)); P = fft_prom(iat); F = min(1.0, P / 8.0)
    S = 1 - min(1.0, mad_ratio(b)); R = 1.0 / max(n_src, 1)
    hrs = {int(x // 3600) for x in t}; C = min(1.0, len(hrs) / max(len(cap_hours), 1))
    score = WEIGHTS["T"] * T + WEIGHTS["F"] * F + WEIGHTS["S"] * S + WEIGHTS["R"] * R + WEIGHTS["C"] * C
    return dict(T=T, F=F, P=P, S=S, R=R, C=C, score=score, n=len(merged), median_iat=float(np.median(iat)))

truth = [json.loads(l) for l in open(os.path.join(W, "beacon_truth.jsonl")) if l.strip()]
beacon_ips = {r["dest_ip"] for r in truth[1:] if r.get("dest_ip")}
b_start, b_end = min(r["ts"] for r in truth[1:]), max(r["ts"] for r in truth[1:])
b_win = int(b_start // WIN)

conns = collections.defaultdict(lambda: collections.defaultdict(list))   # window -> (src,dst,dport) -> [(t,bytes)]
cap_hours = collections.defaultdict(set)
for fn in glob.glob(os.path.join(OUT, "*.conns.gz")):
    if os.path.getsize(fn) == 0: continue
    for line in gzip.open(fn, "rt"):
        t, src, dst, sp, dp, proto, bf, bb, pk, last = json.loads(line)
        w = int(t // WIN); cap_hours[w].add(int(t // 3600))
        if proto not in (6, 17) or skip_dst(dst, dp): continue
        conns[w][(src, dst, dp)].append((t, bf))

rows = []
for w, pairs in conns.items():
    by_pair = collections.defaultdict(list); srcs_per_dst = collections.defaultdict(set)
    port_of = collections.defaultdict(collections.Counter)
    for (src, dst, dp), cs in pairs.items():
        by_pair[(src, dst)].extend(cs); srcs_per_dst[dst].add(src); port_of[(src, dst)][dp] += len(cs)
    for (src, dst), cs in by_pair.items():
        m = merge(cs)
        if len(m) < 20 or m[-1][0] - m[0][0] < 1800: continue
        f = features(m, len(srcs_per_dst[dst]), cap_hours[w])
        f.update(window=w, is_beacon=(w == b_win and dst in beacon_ips), beacon_ip_elsewhere=(w != b_win and dst in beacon_ips),
                 port=port_of[(src, dst)].most_common(1)[0][0], _m=m, _nsrc=len(srcs_per_dst[dst]), _src=src, _dst=dst)
        rows.append(f)


def dnet(ip):
    a = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))
THR = 0.80                                  # alert threshold, fixed before any scoring
benign = [r for r in rows if not r["is_beacon"] and not r["beacon_ip_elsewhere"]]
pos = [r for r in rows if r["is_beacon"]]
hours = sum(len(h) for h in cap_hours.values())
per24 = lambda n: round(n / hours * 24, 1)
bestpos = max(pos, key=lambda r: r["score"])
res = {"what": "Combined beacon score v2 prototype. Weights and the 0.80 alert threshold were fixed before any scoring. "
               "Every session other than the labelled beacon is our own unlabelled traffic, treated as benign (so false alarms are an upper bound).",
       "weights": WEIGHTS, "alert_threshold": THR, "captured_hours": hours, "calendar_days": len({w // 4 for w in cap_hours}),
       "six_hour_windows": len(cap_hours), "captured_hours_per_window": sorted(len(h) for h in cap_hours.values()),
       "sessions_scored": len(rows), "benign_sessions": len(benign),
       "rule": "one session = one (source, destination) pair in one 6-hour UTC window with >= 20 check-ins spanning >= 30 min; "
               "connection starts < 5 s apart merged into one check-in; DNS/NTP/SSDP/mDNS/LLMNR/NetBIOS/DHCP and multicast/link-local dropped"}
res["beacon"] = {k: round(bestpos[k], 3) for k in ("T", "F", "P", "S", "R", "C", "score")}
res["beacon"].update(checkins=bestpos["n"], median_gap_s=round(bestpos["median_iat"], 1),
                     other_beacon_session_score=round(min(pos, key=lambda r: r["score"])["score"], 3),
                     other_beacon_session_checkins=min(pos, key=lambda r: r["score"])["n"])
# --- ranking: same sessions, three rankers ---
same_win = [r for r in rows if r["window"] == bestpos["window"]]
def rank(key, pool): return 1 + sum(1 for r in pool if r is not bestpos and r[key] >= bestpos[key])
res["ranking"] = {}
for name, key in (("combined_score", "score"), ("fft_alone", "P"), ("timing_regularity_alone", "T")):
    res["ranking"][name] = {"benign_sessions_scoring_at_or_above_beacon_all_days": sum(1 for r in benign if r[key] >= bestpos[key]),
                            "beacon_rank_in_its_own_window": [rank(key, same_win), len(same_win)]}
print("ranking:", json.dumps(res["ranking"]))
res["beacon_window_top5"] = [{k: (round(r[k], 3) if isinstance(r[k], float) else r[k]) for k in ("port", "n", "median_iat", "T", "F", "S", "R", "C", "score")} | {"is_beacon": r is bestpos}
                             for r in sorted(same_win, key=lambda r: -r["score"])[:5]]
print("beacon window top 5:", [(x["port"], x["n"], round(x["median_iat"]), x["score"], x["is_beacon"]) for x in res["beacon_window_top5"]])
# --- alerts at the fixed threshold ---
flag = [r for r in benign if r["score"] >= THR]
keys = collections.OrderedDict()
for r in sorted(flag, key=lambda r: r["window"]):
    keys.setdefault((dnet(r["_dst"]), r["port"]), r["window"])
first_w = min(cap_hours); day_of = lambda w: (w - first_w) // 4
new_by_day = collections.Counter(day_of(w) for w in keys.values())
res["alerts_at_threshold"] = {
    "beacon_caught": bestpos["score"] >= THR,
    "benign_session_alerts": len(flag), "benign_session_alerts_per_24h_of_capture": per24(len(flag)),
    "distinct_benign_host_pairs": len({(r["_src"], r["_dst"]) for r in flag}),
    "distinct_benign_services_(dest_network+port)": len(keys),
    "new_services_by_capture_day": [new_by_day.get(d, 0) for d in range(max(day_of(w) for w in cap_hours) + 1)],
    "ports": collections.Counter(r["port"] for r in flag).most_common(6)}
res["alerts_at_threshold"]["services_with_private_lan_destination"] = sum(1 for (net, p) in keys if ipaddress.ip_network(net).is_private)
import datetime as _dt
_all_t = [m[0] for r in rows for m in r["_m"]]
res["capture_dates_utc"] = [_dt.datetime.utcfromtimestamp(min(cap_hours[min(cap_hours)]) * 3600).strftime("%Y-%m-%d"),
                            _dt.datetime.utcfromtimestamp(max(cap_hours[max(cap_hours)]) * 3600).strftime("%Y-%m-%d")]
bkey = (dnet(bestpos["_dst"]), bestpos["port"])
res["alerts_at_threshold"]["beacon_service_seen_before_its_window"] = any(k == bkey and w < bestpos["window"] for k, w in keys.items())
print("alerts at 0.80:", json.dumps(res["alerts_at_threshold"]))
res["sensitivity_other_thresholds"] = {str(t): {"beacon_caught": bestpos["score"] >= t, "benign_session_alerts": sum(1 for r in benign if r["score"] >= t),
                                                "per_24h": per24(sum(1 for r in benign if r["score"] >= t))} for t in (0.70, 0.75, 0.85, 0.90)}
print("other thresholds:", res["sensitivity_other_thresholds"])
# --- FFT sanity: what does the FFT term give a perfectly clean beacon? ---
rs = np.random.RandomState(0)
clean = [fft_prom(60 * (1 + rs.uniform(-0.05, 0.05, 230))) for _ in range(200)]
res["fft_check"] = {"clean_simulated_60s_beacon_prominence_median": round(float(np.median(clean)), 2),
                    "benign_sessions_prominence_median": round(float(np.median([r["P"] for r in benign])), 2),
                    "real_beacon_prominence": round(bestpos["P"], 2)}
print("fft check:", res["fft_check"])
# --- simulated variants of the REAL beacon (real sizes, re-timed or thinned check-ins) ---
rng = random.Random(7); base = bestpos["_m"]; med = np.median(np.diff([m[0] for m in base]))
def retime(jit):
    t = base[0][0]; out = []
    for m in base:
        out.append([t, m[1]]); t += med * (1 + rng.uniform(-jit, jit))
    return out
variants = {}
for name, mm in [("jitter_20pct", retime(0.20)), ("jitter_50pct", retime(0.50)),
                 ("drop_20pct_of_checkins", [m for m in base if rng.random() > 0.20]),
                 ("every_5th_checkin_about_5min", base[::5]), ("every_15th_checkin_about_15min", base[::15])]:
    if len(mm) < 20: variants[name] = {"scored": False, "why": f"only {len(mm)} check-ins in the window; the rule needs 20"}; print(" ", name, variants[name]); continue
    f = features(mm, bestpos["_nsrc"], cap_hours[bestpos["window"]])
    variants[name] = {"scored": True, "score": round(f["score"], 3), "caught_at_0.80": f["score"] >= THR,
                      "benign_sessions_at_or_above": sum(1 for r in benign if r["score"] >= f["score"])}
    print(" ", name, variants[name])
res["simulated_variants_of_real_beacon"] = variants
json.dump(res, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2_beacon_score_eval.json"), "w"), indent=1, default=str)
print("saved")
