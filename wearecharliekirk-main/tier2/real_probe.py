#!/usr/bin/env python3
"""real_probe.py -- actually train the Inspector on Deep's captured traffic.

The point is NOT to produce a detection number -- there are no attacks in this
capture and no labels, so no detection number exists. The point is to run the
real pipeline on the real bytes and show, concretely, what the model receives
and what it does with it:

    1. build the (H, D, W, C, F) tensor from the pcaps using the SAME
       EDGE_FEATURES the synthetic and LANL paths use
    2. report how much of that tensor is actually populated
    3. commission the Inspector on the early hours, score the late hours
    4. report the FLAG RATE on known-benign traffic -- the false-positive
       proxy, which IS answerable and IS an industrial metric

Everything about the split here is a smoke test, not an evaluation: H=1 host
and a fraction of one day cannot support the commissioning window the design
calls for.
"""
import sys, os, glob, socket, collections, math, json, argparse
import numpy as np, dpkt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsentinel_v2.zeek_loader import _COMPILED, _PRIVATE
from netsentinel_v2.categories import (CATEGORIES, CAT_INDEX, N_CATEGORIES,
                                       N_EDGE_FEATURES, EDGE_FEATURES)
from netsentinel_v2.synth import _edge_row, WINDOWS_PER_DAY
import netsentinel_v2.train as T
from run_experiment import count_params

RNG = np.random.default_rng(0)
_AP = argparse.ArgumentParser()
_AP.add_argument("--dir", default=os.environ.get("NS_CAPTURE_DIR", r"D:\capture"),
                 help="folder holding ns_*.pcap")
_AP.add_argument("--cache", default="real_capture.npz",
                 help="write the parsed tensor here so inject_demo.py can reuse it")
_AP.add_argument("--no-train", action="store_true",
                 help="parse and cache only; skip commissioning the Inspector")
_A = _AP.parse_args()

CAPDIR = _A.dir
# drop the newest file: dumpcap is still writing it, so it is a partial hour.
FILES = sorted(glob.glob(os.path.join(CAPDIR, "ns_*.pcap")))[:-1]


def categorise(name):
    if not name:
        return "Unknown_External"
    for cat, rx in _COMPILED:
        if rx.search(name):
            return cat
    return "Browse"


def ipstr(b, v6):
    return socket.inet_ntop(socket.AF_INET6 if v6 else socket.AF_INET, b)


def pass_dns():
    """Learn every IP->name mapping first, so a name seen at 15:00 also labels
    the same server contacted at 03:00. Deliberately generous to the model."""
    m = {}
    for p in FILES:
        with open(p, "rb") as f:
            for ts, buf in dpkt.pcapng.Reader(f):
                try:
                    eth = dpkt.ethernet.Ethernet(buf); ip = eth.data
                    L4 = ip.data
                    if not isinstance(L4, dpkt.udp.UDP): continue
                    if 53 not in (L4.sport, L4.dport): continue
                    d = dpkt.dns.DNS(L4.data)
                    for a in d.an:
                        if a.type == dpkt.dns.DNS_A:
                            m[socket.inet_ntoa(a.rdata)] = a.name
                        elif a.type == dpkt.dns.DNS_AAAA:
                            m[socket.inet_ntop(socket.AF_INET6, a.rdata)] = a.name
                except Exception:
                    pass
    return m


def pass_flows(dns):
    """Bucket every packet into (hour, category) -> per-flow accumulators."""
    buckets = collections.defaultdict(lambda: collections.defaultdict(
        lambda: {"up": 0, "down": 0, "t": []}))
    t_min = None
    for p in FILES:
        with open(p, "rb") as f:
            for ts, buf in dpkt.pcapng.Reader(f):
                t_min = ts if t_min is None else min(t_min, ts)
    for p in FILES:
        with open(p, "rb") as f:
            for ts, buf in dpkt.pcapng.Reader(f):
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    v6, wire = False, ip.len
                elif isinstance(ip, dpkt.ip6.IP6):
                    v6, wire = True, ip.plen + 40
                else:
                    continue
                L4 = ip.data
                if isinstance(L4, dpkt.tcp.TCP):   proto, sp, dp = "tcp", L4.sport, L4.dport
                elif isinstance(L4, dpkt.udp.UDP): proto, sp, dp = "udp", L4.sport, L4.dport
                else: continue
                src, dst = ipstr(ip.src, v6), ipstr(ip.dst, v6)
                s_priv, d_priv = bool(_PRIVATE.match(src)), bool(_PRIVATE.match(dst))
                if s_priv and d_priv:
                    cat, peer, out = "Internal", dst, True
                elif not d_priv:
                    cat, peer, out = categorise(dns.get(dst)), dst, True
                elif not s_priv:
                    cat, peer, out = categorise(dns.get(src)), src, False
                else:
                    continue
                hour = int((ts - t_min) // 3600)
                key = (proto, peer, dp if out else sp)
                b = buckets[(hour, cat)][key]
                b["up" if out else "down"] += wire
                b["t"].append(ts)
    return buckets, t_min


def build_tensor(buckets):
    hours = sorted({h for h, _ in buckets})
    n_h = max(hours) + 1
    D = math.ceil(n_h / WINDOWS_PER_DAY)
    E = np.zeros((1, D, WINDOWS_PER_DAY, N_CATEGORIES, N_EDGE_FEATURES), np.float32)
    M = np.zeros((1, D, WINDOWS_PER_DAY, N_CATEGORIES), np.float32)
    for (hour, cat), flows in buckets.items():
        if cat not in CAT_INDEX:
            continue
        d, w = divmod(hour, WINDOWS_PER_DAY)
        if d >= D: continue
        ci = CAT_INDEX[cat]
        up = sum(f["up"] for f in flows.values())
        down = sum(f["down"] for f in flows.values())
        n = len(flows)
        starts = sorted(min(f["t"]) for f in flows.values())
        iats = np.diff(starts) if len(starts) > 2 else np.array([1.0, 1.0, 1.0])
        durs = [max(f["t"]) - min(f["t"]) for f in flows.values()]
        peers = {k[1] for k in flows}
        E[0, d, w, ci] = _edge_row(RNG, n, up, down, iats,
                                   distinct_ratio=len(peers) / max(n, 1),
                                   dur_mean=float(np.mean(durs)) if durs else 0.0)
        M[0, d, w, ci] = 1.0
    return E, M, n_h


def main():
    print("=" * 78)
    print("  REAL-CAPTURE PROBE  --  Deep's laptop, one host")
    print("=" * 78)
    print(f"  files {len(FILES)}")

    dns = pass_dns()
    print(f"  DNS IP->name mappings learned: {len(dns)}")
    buckets, t0 = pass_flows(dns)
    E, M, n_h = build_tensor(buckets)
    H, D, W, C, F = E.shape
    # Parsing 16+ pcaps takes minutes. Cache the tensor so inject_demo.py --
    # and any re-run of this script -- starts from here instead.
    np.savez_compressed(_A.cache, E=E, M=M, n_h=n_h, t0=t0)
    print(f"  cached tensor -> {_A.cache}")
    if _A.no_train:
        return
    print(f"  tensor  H={H}  D={D}  W={W}  C={C}  F={F}   ({n_h} capture hours)")

    live = M.sum(-1) > 0
    print(f"\n  live host-hours              {int(live.sum())} / {H*D*W}"
          f"   ({live.mean()*100:.0f}% -- the rest is padding to a full day)")
    print("\n  category occupancy (host-hours in which the category appears):")
    dead = 0
    for i, c in enumerate(CATEGORIES):
        n = int((M[..., i] > 0).sum())
        if n == 0: dead += 1
        bar = "#" * int(n / max(int(live.sum()), 1) * 40)
        print(f"    {c:<18s}{n:>5d}  {bar}")
    print(f"\n  >> {dead} of {C} categories are COMPLETELY EMPTY.")
    print("     The Inspector's category embedding has nothing to embed for them,")
    print("     and no transition involving them can ever be learned or scored.")

    # ---- commission on the early hours, score the late ones ---------------
    flat = lambda X: X.reshape(-1, *X.shape[2:])
    Ef, Mf = flat(E), flat(M)
    Co = flat(T.compute_cohort(E, M))
    # H=1 so the day axis is the only axis; split the WINDOW axis instead.
    cut = int(n_h * 0.66)
    Ec = Ef[:, :cut]; Mc = Mf[:, :cut]; Cc = Co[:, :cut]
    Et = Ef[:, cut:n_h]; Mt = Mf[:, cut:n_h]; Ct = Co[:, cut:n_h]
    Ec, mu, sd = T.standardise(Ec, Mc)
    Et, *_ = T.standardise(Et, Mt, mu, sd)
    print(f"\n  commissioning hours 0-{cut-1}   |   held-out hours {cut}-{n_h-1}")
    print("  (a real deployment commissions for ~14 DAYS; this is 14 HOURS)")

    print("\n  training the Inspector on real captured traffic ...")
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        insp = T.train_inspector(Ec, Mc, Cc, epochs=14, seed=0)
    Zc, err_c = T.inspector_forward(insp, Ec, Mc, Cc)
    _, err_t = T.inspector_forward(insp, Et, Mt, Ct)
    thr = float(np.quantile(err_c, 0.99))
    lt = (Mt.sum(-1) > 0).reshape(-1)
    flags = (err_t.reshape(-1)[lt] >= thr)
    print(f"  Inspector params             {count_params(insp):,}")
    print(f"  threshold (99th pct)         {thr:.4f}")
    print(f"  held-out live hours          {int(lt.sum())}")
    print(f"  FLAGGED                      {int(flags.sum())}"
          f"  ({flags.mean()*100:.1f}%  -- design target ~1%)")

    print("\n" + "=" * 78)
    print("  WHAT THIS DOES AND DOES NOT MEASURE")
    print("=" * 78)
    print("  Every flagged hour above is a FALSE POSITIVE by construction:")
    print("  there are no attacks in this capture. So this is an alert-noise")
    print("  measurement, and nothing else.")
    print()
    print("  It is NOT a detection rate, and no detection rate is computable")
    print("  from this data, for three independent reasons:")
    print("    1. one host. The cohort / hop-2 term is empty by construction.")
    print("    2. under one day. The design commissions for two weeks.")
    print("    3. zero attack labels. There is no positive class to detect.")
    print()
    print(f"    ... and {dead}/9 categories are empty, so the cross-service")
    print("        sequence -- the entire hypothesis -- cannot fire here.")
    json.dump({"hours": n_h, "live": int(live.sum()), "dead_categories": dead,
               "threshold": thr, "held_out_live": int(lt.sum()),
               "flagged": int(flags.sum()), "flag_rate": float(flags.mean())},
              open("real_probe.json", "w"), indent=2)


if __name__ == "__main__":
    main()
