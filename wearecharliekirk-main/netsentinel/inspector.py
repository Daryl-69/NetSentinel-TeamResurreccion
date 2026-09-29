"""Tier 2 (Inspector-Sentry) on REAL traffic -- the sensor side.

The live sensor already reconstructs every connection. This module turns
those flow / DNS events into connection records (host, peer, hostname, start,
duration, bytes up/down), streams them to ``tier2/inspector_live.py serve``
(which needs PyTorch, so it runs in the Tier 2 Python), and keeps what it
streams back for the Sentinel view: the devices it watches, the Sentry score
of each device's current hour, what was escalated to the Inspector and its
verdicts, plus corpus / model status.

Command line (run from wearecharliekirk-main with the sensor's venv):

    python -m netsentinel.inspector import D:\\capture --baseline --tz +05:30
        the 20-day capture (pcap/pcapng files, or zeekify.sh's Zeek logs)
        -> tier2/data/baseline_corpus.sqlite (hourly windows, hosts pseudonymised)
    python -m netsentinel.inspector import more.pcapng
        -> the live corpus instead (your own devices' past traffic)
    python -m netsentinel.inspector train     # (re)commission now
    python -m netsentinel.inspector status
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import subprocess
import sys
import threading
import time
from typing import Iterable, Optional

from netsentinel.tier2_bridge import TIER2, tier2_python, torch_available

if str(TIER2) not in sys.path:
    sys.path.insert(0, str(TIER2))

from netsentinel_v2 import hostwindows as HW  # noqa: E402  (numpy/scipy only, no torch)


# --------------------------------------------------------------------------
# sensor events -> connection records
# --------------------------------------------------------------------------
class RecordBuilder:
    """Flow + DNS-reply events -> FlowRecord tuples seen from the local host.

    host = the local endpoint: RFC1918 / ULA / link-local, or one of
    `local_ips` (the capture interface's own addresses -- a laptop's global
    IPv6 address matches no private range). Connections with no local
    endpoint (transit traffic on a mirror port) are dropped.
    """

    def __init__(self, local_ips: Iterable[str] = (), dns_cache: int = 50_000):
        self.local = set(local_ips)
        self.dns: collections.OrderedDict = collections.OrderedDict()
        self.dns_cache = dns_cache
        self.records = 0
        self.skipped = 0

    def feed(self, ev: dict) -> Optional[tuple]:
        t = ev.get("type")
        if t == "dns_response":
            name = ev.get("domain")
            for ip in ev.get("answer_ips") or ():
                if name:
                    self.dns[ip] = name
                    self.dns.move_to_end(ip)
            while len(self.dns) > self.dns_cache:
                self.dns.popitem(last=False)
            return None
        if t != "flow":
            return None
        src, dst = ev.get("source_ip"), ev.get("dest_ip")
        ts = ev.get("timestamp")
        if not src or not dst or not ts:
            return None
        f = ev.get("features") or {}
        fwd = float(f.get("Fwd Packets Length Total", 0) or 0)
        bwd = float(f.get("Bwd Packets Length Total", 0) or 0)
        dur = max(0.0, float(ev.get("last_seen") or ts) - float(ts))
        if HW.is_local(src, self.local):
            sni = (ev.get("tls") or {}).get("sni")
            rec = (src, dst, sni or self.dns.get(dst), float(ts), dur, fwd, bwd)
        elif HW.is_local(dst, self.local):
            rec = (dst, src, self.dns.get(src), float(ts), dur, bwd, fwd)
        else:
            self.skipped += 1
            return None
        self.records += 1
        return rec


def interface_addresses(iface: Optional[str]) -> list[str]:
    """Every address (IPv4 and IPv6) of the capture interface."""
    if not iface:
        return []
    try:
        from scapy.all import conf
        i = conf.ifaces.dev_from_name(iface)
    except Exception:
        return []
    out = []
    ips = getattr(i, "ips", None)
    if isinstance(ips, dict):
        for v in ips.values():
            out.extend(str(x) for x in v)
    elif getattr(i, "ip", None):
        out.append(str(i.ip))
    return [a for a in out if a and a not in ("0.0.0.0", "::")]


# --------------------------------------------------------------------------
# the live Tier 2 process
# --------------------------------------------------------------------------
class InspectorLive:
    def __init__(self):
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None
        self.status = "idle"            # idle | starting | running | error | stopped
        self.stage = None
        self.error = None
        self.meta: dict = {}
        self.logs: collections.deque = collections.deque(maxlen=80)
        self.hours: collections.deque = collections.deque(maxlen=240)
        self.flags: collections.deque = collections.deque(maxlen=200)
        self.last_status: dict = {}
        self.seq = 0
        self.builder = RecordBuilder()
        self.pending: collections.deque = collections.deque(maxlen=200_000)
        self.dropped = 0
        self.iface = None

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, iface: Optional[str] = None, own_ips: Iterable[str] = (),
              tick: Optional[float] = None) -> dict:
        if tick is None:
            tick = float(os.environ.get("NETSENTINEL_INSPECTOR_TICK", "30"))
        with self.lock:
            if self.running:
                return {"status": self.status}
            if not (TIER2 / "inspector_live.py").exists():
                self.status, self.error = "error", "tier2/inspector_live.py not found"
                return {"status": self.status, "error": self.error}
            own = list(own_ips) or interface_addresses(iface)
            self.builder = RecordBuilder(own)
            self.iface = iface
            self.status, self.stage, self.error = "starting", None, None
            self.meta, self.seq = {}, 0
            self.logs.clear(); self.hours.clear(); self.flags.clear(); self.pending.clear()
            env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
            try:
                self.proc = subprocess.Popen(
                    [tier2_python(), "-u", "inspector_live.py", "serve", "--tick", str(tick)],
                    cwd=str(TIER2), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                    bufsize=1, env=env)
            except Exception as e:
                self.status, self.error = "error", str(e)[:300]
                return {"status": self.status, "error": self.error}
            self._send({"t": "hello", "own_ips": own, "iface": iface})
        threading.Thread(target=self._read, daemon=True, name="inspector-read").start()
        threading.Thread(target=self._write, daemon=True, name="inspector-write").start()
        return {"status": "starting", "python": tier2_python(), "own_ips": own}

    def observe(self, event: dict) -> None:
        """Called for every live-capture event; cheap, never blocks."""
        if self.proc is None:
            return
        rec = self.builder.feed(event)
        if rec is not None:
            if len(self.pending) == self.pending.maxlen:
                self.dropped += 1
            self.pending.append(rec)

    def retrain(self) -> dict:
        return {"status": "sent" if self._send({"t": "cmd", "c": "retrain"}) else "not running"}

    def stop(self) -> None:
        self._flush()
        self._send({"t": "cmd", "c": "quit"})
        p = self.proc
        if p is not None:
            try:
                p.wait(timeout=10)
            except Exception:
                p.terminate()
        self.status = "stopped"
        self.proc = None                  # observe() becomes a no-op again
        self.pending.clear()

    # ---- plumbing
    def _send(self, obj) -> bool:
        p = self.proc
        if p is None or p.poll() is not None or p.stdin is None:
            return False
        try:
            p.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n"); p.stdin.flush()
            return True
        except Exception:
            return False

    def _flush(self):
        batch = []
        while self.pending and len(batch) < 5000:
            batch.append(self.pending.popleft())
        if batch:
            self._send({"t": "flows", "r": batch})
        return len(batch)

    def _write(self):
        while self.running:
            if not self._flush():
                time.sleep(1.0)

    def _read(self):
        p = self.proc
        tail = collections.deque(maxlen=8)
        for line in p.stdout:                                          # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                tail.append(line)
                continue
            with self.lock:
                t = d.get("type")
                if t == "stage":
                    self.stage = d.get("stage"); self.logs.append(d.get("text"))
                    if self.status == "starting" and self.stage in ("watching", "collecting"):
                        self.status = "running"
                elif t == "log":
                    self.logs.append(d.get("text"))
                elif t == "ready":
                    self.meta = d
                    if self.stage in ("watching", "collecting", None) or self.meta.get("threshold"):
                        self.status = "running"
                        self.stage = self.stage or "watching"
                elif t == "status":
                    self.last_status = d
                elif t == "hour":
                    self.seq += 1
                    d["seq"] = self.seq
                    self.hours.append(d)
                    for v in d.get("verdicts", []):
                        if v.get("flagged"):
                            self.flags.append(dict(v, date=d.get("date"), clock=d["clock"], seq=self.seq,
                                                   final=d.get("final")))
        rc = p.wait()
        with self.lock:
            if self.status != "stopped":
                self.status = "error"
                txt = " ".join(tail)
                self.error = ("PyTorch is not available to %s" % tier2_python()) if "torch" in txt.lower() \
                    else ("the Inspector stopped (exit %s) %s" % (rc, txt[-300:]))

    def state(self, since: int = 0) -> dict:
        with self.lock:
            return {"mode": "real", "status": self.status, "stage": self.stage, "error": self.error,
                    "meta": self.meta, "logs": list(self.logs), "seq": self.seq,
                    "hours": [h for h in self.hours if h["seq"] > since], "flags": list(self.flags),
                    "attack_active": False, "python": tier2_python(), "iface": self.iface,
                    "inspector": self.last_status,
                    "feed": {"records": self.builder.records, "not_local": self.builder.skipped,
                             "queued": len(self.pending), "dropped": self.dropped}}


INSPECTOR = InspectorLive()


def available() -> bool:
    """Tier 2 can run on real traffic: the service script exists and the
    Tier 2 Python has PyTorch."""
    return (TIER2 / "inspector_live.py").exists() and bool(torch_available().get("ok"))


# --------------------------------------------------------------------------
# importing a capture (the 20-day baseline, or your own past traffic)
# --------------------------------------------------------------------------
PCAP_GLOBS = ("*.pcap", "*.pcapng", "*.cap")


def _pcap_files(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for g in PCAP_GLOBS:
                out += glob.glob(os.path.join(p, "**", g), recursive=True)
        elif os.path.isfile(p):
            out.append(p)
    return sorted(set(out))


def _pcap_events(files: list[str]):
    from netsentinel.extractor.pcap_reader import PacketProcessor
    for i, f in enumerate(files, 1):
        print(f"    [{i}/{len(files)}] {os.path.basename(f)}", flush=True)
        pp = PacketProcessor(use_cicflowmeter=False)
        for ev in pp.process_pcap(f):
            if ev is not None:
                yield ev


def detect_local_ips(files: list[str], sample_files: int = 3) -> set:
    """Which addresses are the monitored devices? A device talks to many
    distinct peers; each remote server in a single-site capture talks to a
    handful. Private addresses are always local; this finds the rest (a
    laptop's global IPv6 address)."""
    peers = collections.defaultdict(set)
    step = max(1, len(files) // sample_files)
    sample = files[::step][:sample_files]            # spread over the capture, not just its start
    for ev in _pcap_events(sample):
        if ev.get("type") == "flow" and ev.get("source_ip") and ev.get("dest_ip"):
            peers[ev["source_ip"]].add(ev["dest_ip"])
            peers[ev["dest_ip"]].add(ev["source_ip"])
    if not peers:
        return set()
    top = max(len(v) for v in peers.values())
    return {ip for ip, v in peers.items() if len(v) >= max(10, 0.25 * top) and not HW._PRIVATE.match(ip)}


def import_capture(paths: list[str], to_baseline: bool, tz: Optional[str],
                   local_ips: list[str], detect: bool = True) -> dict:
    import inspector_live as IL                      # tier2/, torch not needed for this
    npzs = [p for p in paths if p.lower().endswith(".npz")]
    corpora = [p for p in paths if p.lower().endswith((".sqlite", ".db"))]
    rest = [p for p in paths if p not in npzs and p not in corpora]
    zeek_roots = [p for p in rest if os.path.isdir(p) and HW.zeek_dirs(p)]
    pcaps = _pcap_files([p for p in rest if p not in zeek_roots])
    if not zeek_roots and not pcaps and not npzs and not corpora:
        raise SystemExit(f"no pcap/pcapng files or Zeek conn logs found in: {' '.join(paths)}")
    path = IL.DEFAULT_BASELINE if to_baseline else os.path.join(IL.DEFAULT_STATE, "live_corpus.sqlite")
    store = HW.CorpusStore(path, tz_offset=HW.parse_tz(tz) if (tz or not os.path.exists(path)) else None)
    print(f"  corpus: {path}  (tz offset {store.tz:+d}s)")
    result = {"corpus_path": path}
    for i, f in enumerate(npzs, 1):
        rows, _tz = HW.rows_from_npz(f)              # raises for old-format files
        print(f"  pcap_to_tensor output: {f}  ({len(rows)} windows)")
        result[f] = {"windows_written": store.put(rows)}
    for i, f in enumerate(corpora, 1):
        tag = os.path.splitext(os.path.basename(f))[0][:12].replace("-", "_")
        print(f"  corpus from another sensor: {f}")
        result[f] = {"windows_written": HW.merge_corpus(f, store, host_prefix=f"{tag}:")}
    for root in zeek_roots:
        print(f"  Zeek logs: {root}")
        result[root] = HW.ingest(HW.records_from_zeek(root, local_ips), store)
    if pcaps:
        loc = set(local_ips)
        if detect and not loc:
            print(f"  finding the monitored devices' own addresses (first files) ...")
            loc = detect_local_ips(pcaps)
            print(f"  local (non-private) addresses: {sorted(loc) or 'none -- private ranges only'}")
        rb = RecordBuilder(loc)
        print(f"  pcap files: {len(pcaps)}")

        def recs():
            for ev in _pcap_events(pcaps):
                r = rb.feed(ev)
                if r is not None:
                    yield HW.FlowRecord(*r)
        res = HW.ingest(recs(), store)
        res["not_local_connections"] = rb.skipped
        result["pcap"] = res
    if to_baseline:
        IL.pseudonymise(store)
    result["corpus"] = store.summary()
    return result


def _tier2(args: list[str]) -> int:
    return subprocess.call([tier2_python(), "inspector_live.py"] + args, cwd=str(TIER2))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m netsentinel.inspector",
                                 description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    im = sub.add_parser("import", help="capture (pcap/pcapng files or Zeek logs) -> corpus")
    im.add_argument("paths", nargs="+", help="pcap/pcapng files or folders, Zeek log folders, "
                    "pcap_to_tensor .npz files, or corpora exported by other sensors (.sqlite)")
    im.add_argument("--baseline", action="store_true",
                    help="write the shipped baseline corpus (tier2/data/), hosts pseudonymised")
    im.add_argument("--tz", default=None, help="capture site's UTC offset, e.g. +05:30 (default: this machine's)")
    im.add_argument("--local-ip", action="append", default=[],
                    help="a monitored device's non-private address (e.g. global IPv6); repeatable")
    im.add_argument("--no-detect", action="store_true", help="don't auto-detect non-private local addresses")
    tr = sub.add_parser("train", help="(re)commission the Inspector now on baseline + live corpus")
    tr.add_argument("--publish", action="store_true",
                    help="also write tier2/data/models/ so the trained model ships with the repo")
    ex = sub.add_parser("export", help="pseudonymised copy of this sensor's live corpus, to pool into a shared baseline")
    ex.add_argument("out", nargs="?", default="netsentinel_corpus_export.sqlite")
    ex.add_argument("--name", default="site", help="prefix for the device aliases (e.g. your site name)")
    tr.add_argument("--from-scratch", action="store_true",
                    help="don't fine-tune the current/shipped model; train new weights")
    sub.add_parser("status", help="corpora and current model")
    a = ap.parse_args(argv)

    if a.cmd == "import":
        res = import_capture(a.paths, a.baseline, a.tz, a.local_ip, detect=not a.no_detect)
        print(json.dumps(res, indent=1, default=str))
        if a.baseline:
            print("\n  Baseline written. Commit tier2/data/baseline_corpus.sqlite so every install starts from it.")
    elif a.cmd == "train":
        sys.exit(_tier2(["train"] + (["--publish"] if a.publish else [])
                        + (["--from-scratch"] if a.from_scratch else [])))
    elif a.cmd == "export":
        import inspector_live as IL
        live = HW.CorpusStore(os.path.join(IL.DEFAULT_STATE, "live_corpus.sqlite"))
        print(json.dumps(HW.export_corpus(live, a.out, a.name), indent=1))
        print(f"\n  Wrote {a.out}. Add it to the shared baseline with:\n"
              f"    python -m netsentinel.inspector import {a.out} --baseline")
    elif a.cmd == "status":
        sys.exit(_tier2(["status"]))


if __name__ == "__main__":
    main()
