"""Fast connection extractor for pcapng captures (dumpcap output).
Per 5-tuple connection: start time, initiator, ports, protocol, bytes each way, packets.
Only aggregate connection metadata is written; no payload."""
import sys, os, struct, gzip, json, socket, glob, time
IDLE = 300.0   # a 5-tuple silent this long starts a new connection

def packets(path):
    data = open(path, "rb").read(); off = 0; n = len(data)
    linktypes, tsres = [], []
    while off + 12 <= n:
        btype, blen = struct.unpack_from("<II", data, off)
        if blen < 12 or off + blen > n: break
        if btype == 0x0A0D0D0A:
            linktypes, tsres = [], []
        elif btype == 1:
            lt = struct.unpack_from("<H", data, off + 8)[0]; res = 1e-6
            o = off + 16
            while o + 4 <= off + blen - 4:
                code, olen = struct.unpack_from("<HH", data, o)
                if code == 0: break
                if code == 9 and olen >= 1:
                    v = data[o + 4]; res = (2.0 ** -(v & 0x7F)) if (v & 0x80) else (10.0 ** -v)
                o += 4 + ((olen + 3) & ~3)
            linktypes.append(lt); tsres.append(res)
        elif btype == 6:
            ifid, hi, lo, cap, orig = struct.unpack_from("<IIIII", data, off + 8)
            if ifid < len(linktypes):
                yield ((hi << 32) | lo) * tsres[ifid], linktypes[ifid], data[off + 28: off + 28 + cap]
        off += blen

def parse(pkt, lt):
    if lt != 1 or len(pkt) < 34: return None
    et = struct.unpack_from("!H", pkt, 12)[0]; o = 14
    if et == 0x8100: et = struct.unpack_from("!H", pkt, 16)[0]; o = 18
    if et == 0x0800:
        ihl = (pkt[o] & 0x0F) * 4; proto = pkt[o + 9]; ln = struct.unpack_from("!H", pkt, o + 2)[0]
        src, dst, t, fam = pkt[o + 12:o + 16], pkt[o + 16:o + 20], o + ihl, socket.AF_INET
    elif et == 0x86DD:
        if len(pkt) < o + 40: return None
        proto = pkt[o + 6]; ln = struct.unpack_from("!H", pkt, o + 4)[0] + 40
        src, dst, t, fam = pkt[o + 8:o + 24], pkt[o + 24:o + 40], o + 40, socket.AF_INET6
        hops = 0
        while proto in (0, 43, 60) and len(pkt) >= t + 2 and hops < 4:
            proto, t = pkt[t], t + (pkt[t + 1] + 1) * 8; hops += 1
    else:
        return None
    if proto in (6, 17) and len(pkt) >= t + 4:
        sp, dp = struct.unpack_from("!HH", pkt, t)
        syn = proto == 6 and len(pkt) > t + 13 and (pkt[t + 13] & 0x12) == 0x02
    else:
        sp = dp = 0; syn = False
    return fam, src, dst, sp, dp, proto, ln, syn

def extract(path, out):
    flows, done = {}, []
    for ts, lt, pkt in packets(path):
        p = parse(pkt, lt)
        if not p: continue
        fam, src, dst, sp, dp, proto, ln, syn = p
        a, b = (src, sp), (dst, dp)
        key = (a, b, proto) if a <= b else (b, a, proto)
        f = flows.get(key)
        if f is None or ts - f[1] > IDLE or (syn and f[8] > 3):
            if f is not None: done.append(f)
            f = [ts, ts, fam, src, dst, sp, dp, proto, 0, 0, 0]   # start,last,fam,isrc,idst,sport,dport,proto,pkts,bfwd,bbwd
            flows[key] = f
        f[1] = ts; f[8] += 1
        if src == f[3] and sp == f[5]: f[9] += ln
        else: f[10] += ln
    done.extend(flows.values())
    with gzip.open(out, "wt") as fh:
        for f in done:
            fam = f[2]
            fh.write(json.dumps([round(f[0], 6), socket.inet_ntop(fam, f[3]), socket.inet_ntop(fam, f[4]),
                                 f[5], f[6], f[7], f[9], f[10], f[8], round(f[1], 6)]) + "\n")
    return len(done)

if __name__ == "__main__":
    outdir = os.path.expanduser("~/scratch/conns/out"); os.makedirs(outdir, exist_ok=True)
    budget = float(sys.argv[1]) if len(sys.argv) > 1 else 150
    t0 = time.time(); todo = sorted(glob.glob(os.path.expanduser("~/mnt/capture/ns_*.pcap")), key=lambda p: (0 if "_20260921" in p and os.path.basename(p)[3:8] in ("00015","00016","00017","00018","00019") and os.path.basename(p)[18:20] in ("00","01","02","03") else 1, p))
    for pth in todo:
        out = os.path.join(outdir, os.path.basename(pth) + ".conns.gz")
        if os.path.exists(out): continue
        if time.time() - t0 > budget: break
        try:
            n = extract(pth, out + ".tmp"); os.replace(out + ".tmp", out)
        except FileNotFoundError:
            open(out, "w").close()   # rotated away by the capture ring buffer; mark as skipped
    left = sum(1 for p in todo if not os.path.exists(os.path.join(outdir, os.path.basename(p) + ".conns.gz")))
    print(f"done this call in {time.time()-t0:.0f}s; files remaining: {left} of {len(todo)}")
