#!/usr/bin/env python3
"""
capture_probe.py -- measure what our capture can and cannot see, honestly.

This replaces the guesswork in the first audit with four measurements that
each answer a question we were previously answering from opinion:

  1. WHAT SNAPLEN WAS ACTUALLY RUNNING?
     pcapng records it per interface. We read it from the file instead of
     trusting what the script says it passes.

  2. HOW BIG ARE OUR TLS ClientHellos REALLY?
     A TLS record announces its own length in the first 5 bytes, which survive
     any snaplen we have ever used. So even a capture that truncated every
     handshake tells us exactly how large those handshakes were. That turns
     "is 512 enough?" into arithmetic. We report the distribution and the
     snaplen that would have captured 100% of them whole.

  3. HOW MANY ClientHellos SPAN MULTIPLE TCP SEGMENTS?
     This is the part no snaplen can fix. If the handshake is split across
     segments, a per-packet parser misses the hostname no matter how many
     bytes it keeps, and only TCP reassembly (Zeek) recovers it. If this
     number is large, the fix is the loader, not the capture flag.

  4. CAN WE NAME QUIC FLOWS?
     Not "is it QUIC", but "did we get a hostname out of it" -- by deriving the
     Initial keys from the published RFC 9001 salt. Plus how many carry
     Encrypted Client Hello, where the visible name is a cover name.

DNS is reported as three separate facts rather than one misleading ratio.
The earlier audit said "55% of DNS went to DoH". That number counted queries
whose NAME was a resolver's hostname, which is the bootstrap lookup a browser
does once before it starts using DoH -- it says nothing about how much DNS was
subsequently hidden. We do not have a defensible denominator for hidden DNS,
so we do not print one.

Usage:
    python capture_probe.py FILE [FILE ...]
    python capture_probe.py --dir D:\\capture [--limit 8] [--out probe.json]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BT_IDB = 0x00000001
BT_EPB = 0x00000006
BT_SHB = 0x0A0D0D0A

# Hostnames that mean "this connection is carrying somebody else's DNS".
DOH_NAMES = (
    "cloudflare-dns.com", "chrome.cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "dns.google", "dns64.dns.google", "dns.quad9.net", "doh.opendns.com",
    "doh.cleanbrowsing.org", "dns.nextdns.io", "doh.dns.sb", "dns.adguard.com",
    "one.one.one.one",
)
DOH_IPS = (
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "94.140.14.14", "208.67.222.222",
)


# ---------------------------------------------------------------- pcapng ----
def blocks(path):
    with open(path, "rb") as f:
        data = f.read()
    i, n, endian = 0, len(data), "<"
    while i + 12 <= n:
        btype = struct.unpack(endian + "I", data[i:i + 4])[0]
        if btype == BT_SHB:
            endian = "<" if data[i + 8:i + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            btype = BT_SHB
        blen = struct.unpack(endian + "I", data[i + 4:i + 8])[0]
        if blen < 12 or i + blen > n:
            break
        yield btype, data[i + 8:i + blen - 4], endian
        i += blen


def read_file(path):
    """Yield ('idb', snaplen) and ('pkt', caplen, origlen, bytes)."""
    for btype, body, endian in blocks(path):
        if btype == BT_IDB:
            linktype, _r, snaplen = struct.unpack(endian + "HHI", body[:8])
            yield ("idb", snaplen, linktype, None)
        elif btype == BT_EPB:
            _if, _th, _tl, caplen, origlen = struct.unpack(endian + "IIIII",
                                                           body[:20])
            yield ("pkt", caplen, origlen, body[20:20 + caplen])


# ------------------------------------------------------------- decoding -----
def eth_ip(pkt):
    """Return (proto, src, dst, l4_offset, l3l4_hdr_len) or None."""
    if len(pkt) < 14:
        return None
    et = struct.unpack("!H", pkt[12:14])[0]
    off = 14
    while et in (0x8100, 0x88A8) and len(pkt) >= off + 4:      # VLAN tags
        et = struct.unpack("!H", pkt[off + 2:off + 4])[0]
        off += 4
    if et == 0x0800:
        if len(pkt) < off + 20:
            return None
        ihl = (pkt[off] & 0x0F) * 4
        proto = pkt[off + 9]
        src = ".".join(str(b) for b in pkt[off + 12:off + 16])
        dst = ".".join(str(b) for b in pkt[off + 16:off + 20])
        return proto, src, dst, off + ihl, off + ihl
    if et == 0x86DD:
        if len(pkt) < off + 40:
            return None
        proto = pkt[off + 6]
        src = pkt[off + 8:off + 24].hex()
        dst = pkt[off + 24:off + 40].hex()
        return proto, src, dst, off + 40, off + 40
    return None


def tls_client_hello(pkt, l4off, origlen):
    """
    If this TCP packet starts a TLS ClientHello, return a dict describing it.
    Uses the ORIGINAL wire length to reason about truncation and segmentation,
    so the answer is correct even on a capture that truncated the payload.
    """
    if len(pkt) < l4off + 20:
        return None
    doff = ((pkt[l4off + 12] >> 4) & 0x0F) * 4
    payoff = l4off + doff
    dport = struct.unpack("!H", pkt[l4off + 2:l4off + 4])[0]
    pay = pkt[payoff:]
    if len(pay) < 6:
        return None
    if pay[0] != 0x16 or pay[1] != 0x03:          # handshake, TLS 1.x record
        return None
    if pay[5] != 0x01:                            # ClientHello
        return None
    rec_len = struct.unpack("!H", pay[3:5])[0]
    hdr_bytes = payoff                            # eth+ip+tcp, never truncated
    ch_total = 5 + rec_len                        # whole TLS record
    payload_on_wire = origlen - hdr_bytes
    spans_segments = ch_total > payload_on_wire
    sni, ech = parse_sni(pay[5:])
    return {
        "dport": dport,
        "record_len": rec_len,
        "ch_total": ch_total,
        "hdr_bytes": hdr_bytes,
        "need_snaplen": hdr_bytes + ch_total,
        "payload_on_wire": payload_on_wire,
        "spans_segments": spans_segments,
        "captured_payload": len(pay),
        "sni": sni,
        "ech": ech,
    }


def parse_sni(hs):
    """hs starts at the handshake type byte. Returns (sni|None, ech_bool)."""
    try:
        if not hs or hs[0] != 0x01:
            return None, False
        body = hs[4:]
        off = 2 + 32
        if off >= len(body):
            return None, False
        off += 1 + body[off]
        cs = struct.unpack("!H", body[off:off + 2])[0]
        off += 2 + cs
        off += 1 + body[off]
        ext_total = struct.unpack("!H", body[off:off + 2])[0]
        off += 2
        end, sni, ech = off + ext_total, None, False
        while off + 4 <= min(end, len(body)):
            et, el = struct.unpack("!HH", body[off:off + 4])
            off += 4
            ed = body[off:off + el]
            if et == 0x0000 and len(ed) >= 5:
                nl = struct.unpack("!H", ed[3:5])[0]
                nm = ed[5:5 + nl]
                if len(nm) == nl:
                    sni = nm.decode("utf-8", errors="replace")
            elif et == 0xFE0D:
                ech = True
            off += el
        return sni, ech
    except Exception:
        return None, False


def dns_qnames(pay):
    try:
        if len(pay) < 12:
            return []
        flags = struct.unpack("!H", pay[2:4])[0]
        if flags & 0x8000:
            return []                                  # response
        qd = struct.unpack("!H", pay[4:6])[0]
        off, out = 12, []
        for _ in range(min(qd, 4)):
            labels = []
            while off < len(pay):
                n = pay[off]
                if n == 0:
                    off += 1
                    break
                if n & 0xC0:
                    off += 2
                    break
                labels.append(pay[off + 1:off + 1 + n].decode("utf-8", "replace"))
                off += 1 + n
            off += 4
            if labels:
                out.append(".".join(labels))
        return out
    except Exception:
        return []


# ----------------------------------------------------------------- main -----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--dir")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="capture_probe.json")
    ap.add_argument("--include-names", action="store_true",
                    help="AUDIT F2: write the top destination hostnames into "
                         "the JSON. OFF by default -- that list identifies the "
                         "capture subjects' browsing and the JSON is a small, "
                         "portable, committed file. The names always print to "
                         "stdout; this only controls what is persisted.")
    a = ap.parse_args()

    files = list(a.files)
    if a.dir:
        files += sorted(glob.glob(os.path.join(a.dir, "ns_*.pcap*")))
    if a.limit:
        files = files[-a.limit:]
    if not files:
        print("no files"); return 2

    try:
        from netsentinel_v2.quic import parse_quic_initial
    except Exception as e:
        print(f"  !! QUIC decryptor unavailable: {e}")
        print("  !! QUIC packets will be COUNTED but not named. Section [2]")
        print("  !!   below is therefore NOT evidence that QUIC is absent.")
        print("  !!   Fix:  pip install cryptography   then re-run.")
        parse_quic_initial = None

    R = {
        "files": [], "packets": 0, "truncated": 0,
        "snaplens": Counter(),
        "ch_total": 0, "ch_sni_ok": 0, "ch_ech": 0,
        "ch_spanning": 0, "ch_need": [],
        "quic_long": 0, "quic_initial_ok": 0, "quic_sni_ok": 0,
        "quic_ech": 0, "quic_fail": Counter(), "quic_names": Counter(),
        "dns_q": 0, "dns_names": Counter(),
        "doh_conn": 0, "doh_bytes": 0,
        "tls_names": Counter(),
    }

    for path in files:
        name = os.path.basename(path)
        npk = 0
        try:
            for rec in read_file(path):
                if rec[0] == "idb":
                    R["snaplens"][rec[1]] += 1
                    continue
                _t, caplen, origlen, pkt = rec
                npk += 1
                R["packets"] += 1
                if caplen < origlen:
                    R["truncated"] += 1
                p = eth_ip(pkt)
                if not p:
                    continue
                proto, src, dst, l4off, _hdr = p

                if proto == 6:
                    ch = tls_client_hello(pkt, l4off, origlen)
                    if ch:
                        R["ch_total"] += 1
                        R["ch_need"].append(ch["need_snaplen"])
                        if ch["spans_segments"]:
                            R["ch_spanning"] += 1
                        if ch["ech"]:
                            R["ch_ech"] += 1
                        if ch["sni"]:
                            R["ch_sni_ok"] += 1
                            R["tls_names"][ch["sni"]] += 1
                            if any(ch["sni"].endswith(d) for d in DOH_NAMES):
                                R["doh_conn"] += 1
                    if dst in DOH_IPS or src in DOH_IPS:
                        R["doh_bytes"] += origlen

                elif proto == 17:
                    if len(pkt) < l4off + 8:
                        continue
                    sp, dp = struct.unpack("!HH", pkt[l4off:l4off + 4])
                    pay = pkt[l4off + 8:]
                    if sp == 53 or dp == 53:
                        for q in dns_qnames(pay):
                            R["dns_q"] += 1
                            R["dns_names"][q] += 1
                    elif dp == 443 or sp == 443:
                        if pay and (pay[0] & 0x80):
                            # Count the packet FIRST. This must not depend on
                            # whether the decryptor imported -- otherwise a
                            # missing `cryptography` reports "0 QUIC packets"
                            # and looks like QUIC vanished from the network.
                            R["quic_long"] += 1
                            if not parse_quic_initial:
                                R["quic_fail"]["decryptor unavailable "
                                               "(pip install cryptography)"] += 1
                                continue
                            r = parse_quic_initial(pay)
                            if r is None:
                                continue
                            if r["ok"]:
                                R["quic_initial_ok"] += 1
                                R["quic_sni_ok"] += 1
                                R["quic_names"][r["sni"]] += 1
                                if any(r["sni"].endswith(d) for d in DOH_NAMES):
                                    R["doh_conn"] += 1
                            else:
                                R["quic_fail"][r["reason"]] += 1
                                if r["ech"]:
                                    R["quic_ech"] += 1
                    if dst in DOH_IPS or src in DOH_IPS:
                        R["doh_bytes"] += origlen
        except Exception as e:
            print(f"  {name}: read error {type(e).__name__}: {e}")
        R["files"].append({"file": name, "packets": npk})

    need = sorted(R["ch_need"])
    def pct(p):
        return need[min(len(need) - 1, int(len(need) * p))] if need else 0

    print()
    print("=" * 74)
    print("  CAPTURE PROBE -- what the sensor can actually see")
    print("=" * 74)
    print(f"  files {len(R['files'])}   packets {R['packets']:,}   "
          f"truncated by snaplen {R['truncated']:,} "
          f"({100.0*R['truncated']/max(R['packets'],1):.1f}%)")
    print(f"  snaplen actually recorded in the files: "
          + ", ".join(f"{k} ({v} interfaces)" for k, v in R["snaplens"].items()))

    print()
    print("  [1] TLS over TCP -- how big are the handshakes really?")
    print(f"      ClientHellos seen                     {R['ch_total']:,}")
    print(f"      hostname recovered                    {R['ch_sni_ok']:,} "
          f"({100.0*R['ch_sni_ok']/max(R['ch_total'],1):.1f}%)")
    if need:
        print(f"      snaplen needed, median                {pct(0.50):,} bytes")
        print(f"      snaplen needed, 95th percentile       {pct(0.95):,} bytes")
        print(f"      snaplen needed, worst case            {need[-1]:,} bytes")
        for cand in (160, 512, 1024, 1500, 2048, 4096):
            ok = sum(1 for x in need if x <= cand)
            print(f"        snaplen {cand:<5} would capture whole   "
                  f"{100.0*ok/len(need):5.1f}%")
    print(f"      ClientHellos split across TCP segments {R['ch_spanning']:,} "
          f"({100.0*R['ch_spanning']/max(R['ch_total'],1):.1f}%)  "
          "<-- no snaplen fixes these")
    print(f"      Encrypted Client Hello present         {R['ch_ech']:,}")

    print()
    print("  [2] QUIC -- can we name it without turning it off?")
    print(f"      long-header QUIC packets              {R['quic_long']:,}")
    print(f"      hostname recovered from Initial       {R['quic_sni_ok']:,}")
    if R["quic_fail"]:
        print("      could not read, by reason:")
        for k, v in R["quic_fail"].most_common(6):
            print(f"        {k:<34} {v:,}")
    print(f"      Encrypted Client Hello present        {R['quic_ech']:,}")

    print()
    print("  [3] DNS -- stated as facts, not as one ratio")
    print(f"      plaintext DNS queries readable        {R['dns_q']:,}")
    print(f"      distinct names asked for              {len(R['dns_names']):,}")
    print(f"      connections to known DoH endpoints    {R['doh_conn']:,}")
    print(f"      bytes to/from known DoH resolver IPs  {R['doh_bytes']:,}")
    print("      NOTE: we do not report a '% of DNS hidden by DoH'. We cannot")
    print("      see hidden queries, so we have no denominator for them. The")
    print("      old 55% figure counted bootstrap lookups OF the resolver's")
    print("      own name and did not mean what it said.")

    allnames = R["tls_names"] + R["quic_names"]
    print()
    print(f"  [4] Named destinations: {len(allnames):,} distinct")
    for n, c in allnames.most_common(12):
        print(f"        {c:>7,}  {n}")

    out = {
        "files": len(R["files"]), "packets": R["packets"],
        "truncated": R["truncated"],
        "snaplens_in_files": dict(R["snaplens"]),
        "tls_clienthello": R["ch_total"],
        "tls_sni_ok": R["ch_sni_ok"],
        "tls_spanning_segments": R["ch_spanning"],
        "tls_ech": R["ch_ech"],
        "snaplen_needed_median": pct(0.50),
        "snaplen_needed_p95": pct(0.95),
        "snaplen_needed_max": need[-1] if need else 0,
        "snaplen_coverage": {str(c): round(100.0 * sum(1 for x in need if x <= c)
                                           / max(len(need), 1), 1)
                             for c in (160, 512, 1024, 1500, 2048, 4096)},
        "quic_long_header": R["quic_long"],
        "quic_sni_ok": R["quic_sni_ok"],
        "quic_ech": R["quic_ech"],
        "quic_fail_reasons": dict(R["quic_fail"]),
        "dns_queries_readable": R["dns_q"],
        "dns_distinct_names": len(R["dns_names"]),
        "doh_connections": R["doh_conn"],
        "doh_bytes_known_resolver_ips": R["doh_bytes"],
        "named_destinations": len(allnames),
        **({"top_named": allnames.most_common(25)} if a.include_names else
           {"top_named_withheld": "AUDIT F2 -- pass --include-names to persist"}),
    }
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
