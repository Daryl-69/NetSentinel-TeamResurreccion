import os, sys, json, gzip, glob, collections, random
W = os.path.expanduser("~/mnt/1_sih26#2/wearecharliekirk-main"); sys.path.insert(0, W); os.chdir(W)
import logging; logging.disable(logging.WARNING)
from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.pipeline.analyzer import FlowAnalyzer
from netsentinel.models.portscan_detector import UPSDDetector
from netsentinel.simulator import traffic_gen as G
S = os.path.expanduser("~/scratch/cmp"); mode = sys.argv[1]; part = sys.argv[2]

def make_an():
    reg = ModelRegistry(); reg.load_all(); an = FlowAnalyzer(reg, AlertManager(max_stored=200000))
    det = an.portscan_router.detector
    if mode == "upsd": det.spsd = None; det.upsd = UPSDDetector()
    elif mode == "rule": det.spsd = None; det.upsd = None          # fan-out backstop only
    return an

def run(an, events):
    out = []
    for ev in events:
        a = an.analyze_flow(ev)
        if a: out.append(a)
    out.extend(an.flush_portscan_buffer() or [])
    return [x for x in out if (x.get("threat_class") or x.get("threat_type") or x.get("threat")) == "Port Scan"]

an = make_an()
if part == "benign":
    evs = []
    for fn in sorted(glob.glob(os.path.join(S, "0*.jsonl.gz")) + glob.glob(os.path.join(S, "f15.jsonl.gz"))):
        for l in gzip.open(fn, "rt"):
            e = json.loads(l); e["type"] = "flow"; evs.append(e)
    evs.sort(key=lambda e: e.get("timestamp") or 0)
    ps = run(an, evs)
    srcs = {e.get("source_ip") for e in evs}
    res = {"flows": len(evs), "sources": len(srcs), "portscan_alerts": len(ps), "sources_flagged": len({x.get("source_ip") for x in ps})}
else:
    random.seed(11); evs = [G.generate_port_scan_flow() for _ in range(500)]
    truth = {e.get("source_ip") for e in evs}
    ps = run(an, evs)
    res = {"flows": len(evs), "scanners": len(truth), "caught": len(truth & {x.get("source_ip") for x in ps})}
print(mode, part, json.dumps(res))
json.dump(res, open(os.path.join(S, f"ps_{mode}_{part}.json"), "w"))
