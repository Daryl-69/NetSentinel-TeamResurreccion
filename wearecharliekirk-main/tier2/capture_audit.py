#!/usr/bin/env python3
"""capture_audit.py -- is this capture usable by NetSentinel at all?

Answers, per hour and in total:
  * did TLS SNI survive the snaplen?              (Service Category Resolver input #1)
  * is cleartext DNS present, and is it DoH'd?     (input #2, the fallback)
  * how much of the traffic is QUIC?               (invisible at any snaplen without decrypt)
  * what fraction of external flows can be NAMED?  (the number that decides everything)
  * what does the category distribution look like? (9 classes in use, or 1?)

This is a DATA-READINESS audit, not a detection evaluation. With one host, no
attack labels and under a day of traffic, no detection number is computable
here and none is printed.
"""
import sys, os, glob, socket, collections, datetime as dt, json, argparse
try:
    import dpkt
except ImportError:
    print("needs dpkt:  .\\.venv\\Scripts\\python.exe -m pip install dpkt"); raise SystemExit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsentinel_v2.zeek_loader import _COMPILED, _PRIVATE
from netsentinel_v2.categories import CATEGORIES

def is_private(ip):
    return bool(_PRIVATE.match(ip))

def categorise(name):
    if name:
        for cat, rx in _COMPILED:
            if rx.search(name):
                return cat
        return "Browse"
    return "Unknown_External"

def ipstr(ip, v6):
    return socket.inet_ntop(socket.AF_INET6 if v6 else socket.AF_INET, ip)

def scan(path, dns_map):
    """One pass. Returns per-file stats; mutates the shared dns_map."""
    s = collections.Counter()
    names = collections.Counter()
    flows = {}                      # (proto,dst,dport) -> packets
    t0 = t1 = None
    with open(path, "rb") as f:
        try:
            rd = dpkt.pcapng.Reader(f)
        except ValueError:
            f.seek(0); rd = dpkt.pcap.Reader(f)
        for ts, buf in rd:
            s["packets"] += 1
            s["bytes_on_wire"] += len(buf)
            t0 = ts if t0 is None else min(t0, ts)
            t1 = ts if t1 is None else max(t1, ts)
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                s["unparsed"] += 1; continue
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):
                v6 = False; s["ipv4"] += 1
            elif isinstance(ip, dpkt.ip6.IP6):
                v6 = True; s["ipv6"] += 1
            else:
                s["non_ip"] += 1; continue
            dst = ipstr(ip.dst, v6)
            L4 = ip.data
            if isinstance(L4, dpkt.tcp.TCP):
                s["tcp"] += 1
                if L4.dport == 443: s["tcp443"] += 1
                p = L4.data
                # TLS ClientHello?
                if len(p) >= 6 and p[0] == 0x16 and p[5] == 0x01:
                    s["clienthello"] += 1
                    rec = int.from_bytes(p[3:5], "big")
                    if len(p) < rec + 5:
                        s["ch_truncated"] += 1
                    try:
                        h = dpkt.ssl.TLSHandshake(p[5:])
                        for t, d in h.data.extensions:
                            if t == 0:
                                s["sni_ok"] += 1
                                names[d[5:].decode("utf8", "replace")] += 1
                    except Exception:
                        s["sni_unreadable"] += 1
                if not is_private(dst):
                    flows[("tcp", dst, L4.dport)] = flows.get(("tcp", dst, L4.dport), 0) + 1
            elif isinstance(L4, dpkt.udp.UDP):
                s["udp"] += 1
                if 443 in (L4.sport, L4.dport): s["quic"] += 1
                if 53 in (L4.sport, L4.dport):
                    s["dns_pkts"] += 1
                    try:
                        d = dpkt.dns.DNS(L4.data)
                        for q in d.qd:
                            s["dns_queries"] += 1
                            names[q.name] += 1
                        for a in d.an:
                            if a.type == dpkt.dns.DNS_A:
                                dns_map[socket.inet_ntoa(a.rdata)] = a.name
                            elif a.type == dpkt.dns.DNS_AAAA:
                                dns_map[socket.inet_ntop(socket.AF_INET6, a.rdata)] = a.name
                    except Exception:
                        s["dns_unparseable"] += 1
                if not is_private(dst):
                    flows[("udp", dst, L4.dport)] = flows.get(("udp", dst, L4.dport), 0) + 1
    return s, names, flows, t0, t1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=r"D:\capture", help="folder holding ns_*.pcap")
    ap.add_argument("--out", default="capture_audit.json")
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.dir, "ns_*.pcap")))
    # dumpcap is still writing the newest file; reading it is fine but it is
    # a partial hour and skews the per-hour table.
    files = files[:-1] if len(files) > 1 else files
    if not files:
        print("no staged pcaps found"); return
    dns_map = {}
    per, all_names, all_flows = [], collections.Counter(), {}
    tot = collections.Counter()

    # Pass 1 chronologically so DNS answers are learned before the flows that
    # use them. A name learned in hour 3 still labels an IP seen in hour 9 --
    # that is exactly how Zeek's own dns->conn correlation behaves.
    for p in files:
        s, nm, fl, t0, t1 = scan(p, dns_map)
        per.append((os.path.basename(p), s, t0, t1))
        all_names.update(nm); tot.update(s)
        for k, v in fl.items(): all_flows[k] = all_flows.get(k, 0) + v

    print("=" * 78)
    print("  CAPTURE READINESS AUDIT  --  D:\\capture")
    print("=" * 78)
    print(f"\n  files sampled  {len(files)}")
    hrs = sorted((t0, t1) for _, _, t0, t1 in per if t0)
    if hrs:
        span = (hrs[-1][1] - hrs[0][0]) / 3600
        print(f"  span           {dt.datetime.utcfromtimestamp(hrs[0][0])}"
              f"  ->  {dt.datetime.utcfromtimestamp(hrs[-1][1])}   ({span:.1f} h)")
    print(f"  packets        {tot['packets']:,}")
    print(f"  bytes on wire  {tot['bytes_on_wire']/1e9:.2f} GB (truncated frames)")

    print("\n" + "-" * 78)
    print("  PER HOUR")
    print("-" * 78)
    print(f"  {'file':<30s}{'pkts':>10s}{'QUIC%':>8s}{'DNSq':>7s}{'CHello':>8s}{'SNI':>6s}")
    for name, s, t0, t1 in per:
        q = s["quic"] / max(s["packets"], 1) * 100
        print(f"  {name:<30s}{s['packets']:>10,}{q:>7.0f}%{s['dns_queries']:>7,}"
              f"{s['clienthello']:>8,}{s['sni_ok']:>6,}")

    print("\n" + "-" * 78)
    print("  DEFECT 1 -- TLS SNI")
    print("-" * 78)
    ch, cut, ok = tot["clienthello"], tot["ch_truncated"], tot["sni_ok"]
    print(f"  TLS ClientHellos seen        {ch:,}")
    print(f"  records truncated by snaplen {cut:,}  ({cut/max(ch,1)*100:.0f}%)")
    print(f"  SNI hostnames extracted      {ok:,}  ({ok/max(ch,1)*100:.1f}%)")
    print("  -> snaplen 160 cuts the frame at 160 bytes. Eth+IP+TCP is 54, so the")
    print("     TLS record gets ~106 bytes; a ClientHello spends ~112 on version,")
    print("     random, session id and ciphers BEFORE the extensions block where")
    print("     SNI lives. The hostname is never on disk.")

    print("\n" + "-" * 78)
    print("  DEFECT 2 -- QUIC")
    print("-" * 78)
    q, t = tot["quic"], tot["tcp443"]
    print(f"  UDP/443 (QUIC) packets       {q:,}")
    print(f"  TCP/443 packets              {t:,}")
    print(f"  QUIC share of encrypted web  {q/max(q+t,1)*100:.0f}%")
    print("  -> QUIC carries its SNI inside an encrypted Initial packet. Even at")
    print("     full snaplen Zeek must decrypt it; below Zeek 6 it cannot. Every")
    print("     one of these is invisible to the resolver.")

    print("\n" + "-" * 78)
    print("  DEFECT 3 -- DNS / DoH")
    print("-" * 78)
    print(f"  cleartext DNS packets        {tot['dns_pkts']:,}")
    print(f"  queries parsed               {tot['dns_queries']:,}")
    print(f"  unparseable (truncated)      {tot['dns_unparseable']:,}")
    print(f"  IP -> hostname pairs learned {len(dns_map):,}")
    doh = sum(c for n, c in all_names.items()
              if any(k in n.lower() for k in
                     ("cloudflare-dns", "dns.google", "doh", "dns.quad9",
                      "one.one.one.one", "mozilla.cloudflare")))
    print(f"  queries FOR a DoH resolver   {doh:,}  "
          f"({doh/max(tot['dns_queries'],1)*100:.0f}% of all queries)")
    print("  -> every query that browser resolves over DoH is invisible here. The")
    print("     cleartext DNS we can see is mostly OS-level, not browsing.")

    print("\n" + "-" * 78)
    print("  THE NUMBER THAT DECIDES EVERYTHING -- can flows be NAMED?")
    print("-" * 78)
    named = unnamed = 0
    cat_pkts = collections.Counter()
    for (proto, dst, dport), n in all_flows.items():
        nm = dns_map.get(dst)
        if nm: named += n
        else:  unnamed += n
        cat_pkts[categorise(nm)] += n
    tot_ext = named + unnamed
    print(f"  external packets             {tot_ext:,}")
    print(f"  resolvable to a hostname     {named:,}  ({named/max(tot_ext,1)*100:.1f}%)")
    print(f"  NOT resolvable               {unnamed:,}  ({unnamed/max(tot_ext,1)*100:.1f}%)")

    print("\n  category distribution the model would actually receive:")
    for c in CATEGORIES:
        v = cat_pkts.get(c, 0)
        bar = "#" * int(v / max(tot_ext, 1) * 50)
        print(f"    {c:<18s}{v:>10,}  {v/max(tot_ext,1)*100:5.1f}%  {bar}")

    print("\n  most-contacted named destinations:")
    byname = collections.Counter()
    for (proto, dst, dport), n in all_flows.items():
        nm = dns_map.get(dst)
        if nm: byname[nm] += n
    for nm, c in byname.most_common(15):
        print(f"    {c:>8,}  {categorise(nm):<18s}{nm}")

    json.dump({"files": len(files), "packets": tot["packets"],
               "clienthello": ch, "sni_ok": ok, "quic": q, "tcp443": t,
               "dns_queries": tot["dns_queries"], "dns_map": len(dns_map),
               "named_pkts": named, "unnamed_pkts": unnamed,
               "categories": dict(cat_pkts)},
              open(a.out, "w"), indent=2)
    print(f"\n  -> {a.out}")


if __name__ == "__main__":
    main()
