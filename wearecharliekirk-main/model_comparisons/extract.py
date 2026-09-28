import os, sys, json, gzip, time
W = os.path.expanduser("~/mnt/1_sih26#2/wearecharliekirk-main")
sys.path.insert(0, W); os.chdir(W)
import logging; logging.disable(logging.WARNING)
from netsentinel.extractor import PacketProcessor
src = sys.argv[1]; out = sys.argv[2]
pp = PacketProcessor(); n = 0; t0 = time.time()
with gzip.open(os.path.abspath(out) if os.path.isabs(out) else os.path.join(os.path.expanduser("~/scratch/cmp"), out), "wt") as fh:
    for ev in pp.process_pcap(src):
        if not ev or ev.get("type", "flow") != "flow":
            continue
        rec = {k: ev.get(k) for k in ("source_ip", "dest_ip", "source_port", "dest_port", "protocol", "timestamp", "last_seen")}
        rec["features"] = ev.get("features", {})
        fh.write(json.dumps(rec, default=float) + "\n"); n += 1
print(f"{os.path.basename(src)}: {n} flow events in {time.time()-t0:.0f}s -> {out}")
