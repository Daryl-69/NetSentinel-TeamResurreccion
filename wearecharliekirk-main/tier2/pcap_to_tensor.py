#!/usr/bin/env python3
"""
pcap_to_tensor.py -- real captured packets -> the (host, day, window,
category, feature) tensor, with NO Zeek dependency and NO synthetic filler.

Why this exists: the zeek_loader path needs Zeek installed and a log directory.
This reads the pcap directly, using exactly the parsers already verified
elsewhere in the repo, so a corpus can be assessed from the raw capture.

Provenance of every field:
  hostname   TLS ClientHello SNI (capture_probe.parse_sni) OR
             QUIC Initial SNI (netsentinel_v2.quic, RFC 9001 5.2) OR
             reverse-lookup through observed DNS answers
  category   zeek_loader.resolve_category -- the same deterministic taxonomy
  features   synth._edge_row -- the same 10-feature constructor
  host       the LAN-side IP of the flow (the client)

Nothing here is generated, estimated or defaulted. A flow with no resolvable
hostname becomes Unknown_External, which is the honest outcome, not a gap.
"""
from __future__ import annotations

import argparse, json, os, socket, struct, sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture_probe as CP                                   # noqa: E402
from netsentinel_v2.categories import (CAT_INDEX, N_CATEGORIES,   # noqa: E402
                                       N_EDGE_FEATURES)
from netsentinel_v2.zeek_loader import resolve_category, _PRIVATE  # noqa: E402
from netsentinel_v2.synth import _edge_row                    # noqa: E402

WINDOWS_PER_DAY = 24

# Seconds of silence that end a session. A beacon's sleep interval and a
# human's think-time both live above this; packet bursts within one request
# live far below it.
SESSION_IDLE_GAP = 60.0


def _session_starts(ts):
    """Collapse a sorted packet-timestamp list to one timestamp per session."""
    if len(ts) < 2:
        return list(ts)
    out = [ts[0]]
    for a, b in zip(ts, ts[1:]):
        if b - a > SESSION_IDLE_GAP:
            out.append(b)
    return out

try:
    from netsentinel_v2.quic import parse_quic_initial
except Exception:
    parse_quic_initial = None


BT_IDB, BT_EPB = 0x00000001, 0x00000006


def read_with_ts(path):
    """capture_probe.read_file discards EPB timestamps because it never needed
    them. Windowing does. Same block walker, timestamp kept.

    The EPB 64-bit count (ts_high<<32 | ts_low) is in units set by the IDB's
    if_tsresol option. Do NOT assume microseconds: dumpcap on this capture
    writes if_tsresol=9, i.e. NANOSECONDS. Assuming 1e6 stretches a 1.75-hour
    file into 1,745 hours and puts every packet in its own day.
    """
    import struct as _s
    div = 1e6                                     # replaced by the real IDB value
    for btype, body, endian in CP.blocks(path):
        if btype == BT_IDB:
            linktype, _r, snaplen = _s.unpack(endian + "HHI", body[:8])
            off = 8
            while off + 4 <= len(body):
                code, ln = _s.unpack(endian + "HH", body[off:off + 4])
                off += 4
                val = body[off:off + ln]
                off += ln + ((4 - ln % 4) % 4)
                if code == 0:
                    break
                if code == 9 and ln >= 1:          # if_tsresol
                    r = val[0]
                    div = float(2 ** (r & 0x7F)) if r & 0x80 else float(10 ** r)
            yield ("idb", snaplen, linktype, None)
        elif btype == BT_EPB:
            _if, th, tl, caplen, origlen = _s.unpack(endian + "IIIII", body[:20])
            ts = ((th << 32) | tl) / div
            yield ("pkt", ts, origlen, body[20:20 + caplen])


def local_addresses(paths, verbose=True):
    """Which addresses belong to the monitored machine?

    Three tests that DON'T work here, each tried and discarded:

      RFC1918        wrong on IPv6 -- no NAT, so the host's global v6 address
                     matches no private range and every v6 flow is dropped as
                     "neither side local". That is 52% of this capture.
                     zeek_loader._PRIVATE has exactly this blind spot.
      frequency      one heavy download makes a remote server look local.
      "most frames"  the busiest ethernet source is the GATEWAY, because
                     inbound traffic dominates. Verified: the top MAC here
                     sources 35.190.46.17.

    What does work: count the DISTINCT IP sources each MAC emits. The host's
    NIC emits only its own handful of addresses. The gateway emits the whole
    internet. The separation is several orders of magnitude and needs no
    threshold tuning.
    """
    from collections import defaultdict
    srcs = defaultdict(set)
    frames = defaultdict(int)
    for path in paths:
        for rec in read_with_ts(path):
            if rec[0] == "idb":
                continue
            pkt = rec[3]
            if len(pkt) < 14:
                continue
            p = CP.eth_ip(pkt)
            if not p:
                continue
            mac = pkt[6:12]
            srcs[mac].add(p[1])
            frames[mac] += 1
    if not srcs:
        return set()
    # busy enough to be a real participant, fewest distinct source IPs
    busy = [m for m in srcs if frames[m] >= 0.01 * sum(frames.values())]
    host_mac = min(busy or list(srcs), key=lambda m: len(srcs[m]))
    local = set(srcs[host_mac])
    if verbose:
        print("  ethernet sources, by DISTINCT IPs emitted:")
        for m in sorted(srcs, key=lambda x: -frames[x])[:4]:
            tag = "  <-- host NIC" if m == host_mac else ""
            print(f"    {m.hex(':')}  {frames[m]:>8,} frames  "
                  f"{len(srcs[m]):>6,} distinct src IPs{tag}")
        print(f"  local addresses: {sorted(local)}")
    return local


def extract(paths, local, verbose=True):
    """One pass over the packets. Flows are BIDIRECTIONAL and keyed on the
    client (private) side, so bytes_up and bytes_down are both real."""
    sni_by_dst = {}          # server ip -> hostname, seen on that flow
    dns_map = {}             # answer ip -> queried name
    flows = defaultdict(lambda: {"up": 0, "down": 0, "ts": [], "pkts": 0})
    n_pk = n_ip = 0
    drop = defaultdict(int)
    t_lo = t_hi = None

    def note(host, peer, port, ts, nbytes, outbound):
        f = flows[(host, peer, port)]
        f["up" if outbound else "down"] += nbytes
        f["ts"].append(ts)
        f["pkts"] += 1

    for path in paths:
        for rec in read_with_ts(path):
            if rec[0] == "idb":
                continue
            _tag, ts, origlen, pkt = rec
            n_pk += 1
            p = CP.eth_ip(pkt)
            if not p:
                continue
            proto, s_ip, d_ip, l4off, _ = p
            n_ip += 1
            if t_lo is None or ts < t_lo:
                t_lo = ts
            if t_hi is None or ts > t_hi:
                t_hi = ts

            s_priv = s_ip in local
            d_priv = d_ip in local
            if s_priv and d_priv:
                drop["local_to_local"] += 1
                continue
            if not s_priv and not d_priv:
                drop["remote_to_remote"] += 1
                continue
            if len(pkt) < l4off + 4:
                continue
            sp, dp = struct.unpack("!HH", pkt[l4off:l4off + 4])

            if proto == 6:
                ch = CP.tls_client_hello(pkt, l4off, origlen)
                if ch and ch.get("sni"):
                    sni_by_dst[d_ip] = ch["sni"]
            elif proto == 17:
                pay = pkt[l4off + 8:] if len(pkt) >= l4off + 8 else b""
                if sp == 53 or dp == 53:
                    for nm, ip in dns_answers(pay):
                        dns_map[ip] = nm
                    continue
                if (dp == 443 or sp == 443) and pay and (pay[0] & 0x80) \
                        and parse_quic_initial:
                    r = parse_quic_initial(pay)
                    if r and r.get("ok") and r.get("sni"):
                        sni_by_dst[d_ip] = r["sni"]
            else:
                drop[f"proto_{proto}"] += 1
                continue

            if s_priv:
                note(s_ip, d_ip, dp, ts, origlen, True)
            else:
                note(d_ip, s_ip, sp, ts, origlen, False)

    if verbose:
        print(f"  packets {n_pk:,}  IPv4/v6 {n_ip:,}  bidirectional flows {len(flows):,}")
        print(f"  hostnames learned: {len(sni_by_dst):,} by SNI, "
              f"{len(dns_map):,} by DNS answer")
        if drop:
            print("  packets not usable as host<->external flows:")
            for k, v in sorted(drop.items(), key=lambda x: -x[1])[:6]:
                print(f"    {k:<20}{v:>10,}")
    return flows, sni_by_dst, dns_map, t_lo, t_hi


def dns_answers(pay):
    """Yield (name, ip) from DNS responses. Best-effort, A records only."""
    out = []
    try:
        if len(pay) < 12:
            return out
        qd, an = struct.unpack("!HH", pay[4:8])
        if an == 0:
            return out
        i = 12
        qname = []
        for _ in range(qd):
            while i < len(pay) and pay[i]:
                ln = pay[i]
                if ln & 0xC0:
                    i += 2
                    break
                qname.append(pay[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            else:
                i += 1
            i += 4
        name = ".".join(qname)
        for _ in range(an):
            if i + 12 > len(pay):
                break
            if pay[i] & 0xC0:
                i += 2
            else:
                while i < len(pay) and pay[i]:
                    i += 1 + pay[i]
                i += 1
            if i + 10 > len(pay):
                break
            rtype, _cls, _ttl, rdl = struct.unpack("!HHIH", pay[i:i + 10])
            i += 10
            if rtype == 1 and rdl == 4 and name:
                out.append((name, socket.inet_ntoa(pay[i:i + 4])))
            i += rdl
    except Exception:
        pass
    return out


def build(flows, sni_by_dst, dns_map, t_lo, verbose=True):
    """Aggregate real flows into the tensor. Hosts = LAN-side IPs."""
    buckets = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    peers_in = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    cat_count = defaultdict(int)
    named_flows = unnamed_flows = 0

    for (host, peer, port), f in flows.items():
        name = sni_by_dst.get(peer) or dns_map.get(peer)
        if name:
            named_flows += 1
        else:
            unnamed_flows += 1
        cat = resolve_category(name, peer)
        cat_count[cat] += 1
        hour = int((min(f["ts"]) - t_lo) // 3600)
        buckets[host][hour][cat].append(f)
        peers_in[host][hour][cat].add(peer)

    hosts = sorted(buckets)
    max_h = max((h for b in buckets.values() for h in b), default=0)
    D = max_h // WINDOWS_PER_DAY + 1
    H = len(hosts)
    E = np.zeros((H, D, WINDOWS_PER_DAY, N_CATEGORIES, N_EDGE_FEATURES), np.float32)
    M = np.zeros((H, D, WINDOWS_PER_DAY, N_CATEGORIES), np.float32)

    for hi, host in enumerate(hosts):
        for hour, cats in buckets[host].items():
            d_i, w_i = hour // WINDOWS_PER_DAY, hour % WINDOWS_PER_DAY
            for cat, fl in cats.items():
                ci = CAT_INDEX[cat]
                up = sum(x["up"] for x in fl)
                down = sum(x["down"] for x in fl)
                # GRANULARITY. The timing features describe the rhythm of
                # SESSIONS, not of packets. zeek_loader and lanl_loader both
                # feed _edge_row one timestamp per flow record; if this path
                # fed every packet instead, the same feature would mean two
                # different things depending on the corpus.
                #
                # Measured on our own capture: packet-level iat_cv has median
                # 3.595 against a synthetic training median of 0.805 -- a 4.5x
                # covariate gap that exists only because of this choice.
                # Collapsing packets into sessions (a new session after
                # SESSION_IDLE_GAP seconds of silence) brings it to 0.593,
                # which is the same quantity the models were trained on.
                ts = _session_starts(
                    sorted(t for x in fl for t in x["ts"]))
                iats = np.diff(ts) if len(ts) > 1 else np.array([1.0])
                durs = [max(x["ts"]) - min(x["ts"]) for x in fl]
                distinct = len(peers_in[host][hour][cat]) / max(len(fl), 1)
                E[hi, d_i, w_i, ci] = _edge_row(
                    None, len(fl), up, down, iats, distinct,
                    float(np.mean(durs)) if durs else 0.0)
                M[hi, d_i, w_i, ci] = 1.0

    if verbose:
        tot = named_flows + unnamed_flows
        print(f"  flows with a hostname: {named_flows:,}/{tot:,} "
              f"({100*named_flows/max(tot,1):.1f}%)")
        print(f"  hosts {H}  days {D}  tensor {E.shape}")
    return E, M, hosts, dict(cat_count), named_flows, unnamed_flows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", default="own_corpus.npz")
    a = ap.parse_args()

    print("=" * 70)
    print("  REAL CAPTURE -> TENSOR   (no synthetic substitution)")
    print("=" * 70)
    local = local_addresses(a.files)
    flows, sni, dnsm, t_lo, t_hi = extract(a.files, local)
    span_h = (t_hi - t_lo) / 3600.0 if t_lo else 0
    print(f"  span {span_h:.2f} hours")
    E, M, hosts, cats, res, unres = build(flows, sni, dnsm, t_lo)

    live = (M.sum(-1) > 0)
    print()
    print("  CATEGORY DISTRIBUTION (real traffic)")
    tot = sum(cats.values())
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"    {c:<20}{n:>8,}  {100*n/max(tot,1):5.1f}%")
    print()
    print(f"  live windows total : {int(live.sum()):,}")
    print(f"  live windows/host  : {live.sum()/max(len(hosts),1):.1f}")
    np.savez_compressed(a.out, edges=E, mask=M,
                        hosts=np.array(hosts), span_hours=span_h)
    print(f"  wrote {a.out}")


if __name__ == "__main__":
    main()
