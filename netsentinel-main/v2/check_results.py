#!/usr/bin/env python3
"""Compare this machine's results.json against the reference run.

Kept as its own file on purpose: embedding Python inside a PowerShell
here-string is how verify.ps1 broke the first time.
"""
import json
import sys

REFERENCE = {
    "A_distilled_detector":  0.876,
    "C_deferral_head":       0.850,
    "B_encoder_mahalanobis": 0.818,
}
TOL = 0.04

path = sys.argv[1] if len(sys.argv) > 1 else "results.json"
try:
    d = json.load(open(path))
except Exception as e:
    print("could not read %s: %s" % (path, e))
    sys.exit(1)

got = d["router_auc"]
print("router                     reference   this machine     delta")
ok = True
for k in ("A_distilled_detector", "C_deferral_head", "B_encoder_mahalanobis"):
    ref, g = REFERENCE[k], got[k]
    dlt = g - ref
    out_of_range = abs(dlt) > TOL
    if out_of_range:
        ok = False
    print("  %-24s %9.3f %14.3f %9.3f%s"
          % (k, ref, g, dlt, "   << OUT OF RANGE" if out_of_range else ""))

print("")
print("oracle AUC vs attack : %.3f   (reference 0.875)" % d["oracle_auc"])
print("kNN overlap          : %.3f   (reference 0.346)" % d["geometry_mean"]["knn_overlap@20"])
print("geometry verdict     : %s" % d["verdict"][0])

i5 = d["budgets"].index(0.05)
rec = d["aggregate"]["A_distilled_detector"][i5]["recall_teacher_mean"]
print("A recall @5%% budget  : %.1f%%   (reference 37.1%%)" % (rec * 100))

best = max(got, key=got.get)
print("winner on this machine: %s" % best)
print("")

if ok and best == "A_distilled_detector":
    print("=== RESULT: REPRODUCED ===")
    print("The numbers in the docs are trustworthy on your hardware.")
else:
    print("=== RESULT: MISMATCH ===")
    print("Send verify_log.txt to Claude before trusting any figure in the docs.")
