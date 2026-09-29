#!/usr/bin/env python3
"""Self-test for the real-traffic Inspector path (hostwindows + inspector_live).

Run:  python test_inspector_live.py
Exits non-zero on any failure.

What it pins down, because each is a way to get a confident wrong answer:
  * windows are clock-aligned to the capture site's LOCAL hour (IST is +5:30,
    so UTC-hour windows would split every working hour in two);
  * a window's features are exactly zeek_loader's (_edge_row on one timestamp
    per connection), whichever path built it;
  * the host is the LOCAL endpoint, and a reply-direction connection has its
    bytes swapped, not double-counted as a second host;
  * DNS answers name peers reached without SNI, and carry across hourly folders;
  * flagged windows never reach training;
  * cohort context never mixes two different networks;
  * a trained bundle survives save/load and flags a planted LOTS-chain hour.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from netsentinel_v2 import hostwindows as HW  # noqa: E402
from netsentinel_v2.categories import CAT_INDEX  # noqa: E402
from netsentinel_v2.synth import _edge_row  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(f"  [{'ok ' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    if not cond:
        FAIL.append(name)


IST = 19800
T0 = 1788825600 - IST          # 2026-09-08 00:00 IST


def test_time():
    print("\nlocal-hour alignment")
    check("parse_tz +05:30", HW.parse_tz("+05:30") == 19800)
    check("parse_tz -4", HW.parse_tz("-4") == -14400)
    check("parse_tz seconds", HW.parse_tz("3600") == 3600)
    lh = HW.local_hour(T0 + 9 * 3600 + 10, IST)
    check("09:00:10 IST is hour 9 of its day", lh % 24 == 9, str(lh % 24))
    lh2 = HW.local_hour(T0 + 9 * 3600 - 10, IST)
    check("08:59:50 IST is hour 8", lh2 % 24 == 8)


def test_aggregator():
    print("\nwindow features = zeek_loader's")
    agg = HW.WindowAggregator(IST)
    ts = [T0 + 10 * 3600 + s for s in (5, 65, 125, 190, 250)]
    for t in ts:
        agg.add(HW.FlowRecord("10.0.0.5", "140.82.1.1", "github.com", t, 2.0, 100, 1000))
    agg.add(HW.FlowRecord("10.0.0.5", "140.82.1.2", "github.com", T0 + 10 * 3600 + 300, 4.0, 50, 50))
    rows = agg.rows()
    check("one window", len(rows) == 1, str(len(rows)))
    h, lh, c, n, f = rows[0]
    check("category from the resolver", c == CAT_INDEX["Code_Repo_Paste"])
    starts = np.array(ts + [T0 + 10 * 3600 + 300], dtype=float)
    want = _edge_row(None, 6, 550, 5050, np.diff(np.sort(starts)), 2 / 6, 14.0 / 6)
    check("features identical to _edge_row", np.allclose(f, want), f"{f} vs {want}")
    agg.add(HW.FlowRecord("10.0.0.5", "8.8.8.8", None, T0 + 11 * 3600 + 1, 1, 1, 1))
    closed = agg.pop_before(HW.local_hour(T0 + 11 * 3600, IST))
    check("pop_before closes only earlier hours", len(closed) == 1 and len(agg.acc) == 1)
    check("raw IP, no name -> Unknown_External",
          agg.rows()[0][2] == CAT_INDEX["Unknown_External"])


def _zeek_fixture(root):
    hdr = "#separator \\x09\n#fields\t{}\n"
    a = os.path.join(root, "cap_01")
    b = os.path.join(root, "cap_02")
    os.makedirs(a); os.makedirs(b)
    with open(os.path.join(a, "conn.log"), "w") as f:
        f.write(hdr.format("ts\tuid\tid.orig_h\tid.resp_h\tduration\torig_bytes\tresp_bytes"))
        f.write(f"{T0 + 9 * 3600 + 5}\tC1\t192.168.1.10\t140.82.1.1\t1.0\t100\t9000\n")
        # inbound: remote originator -> the local host is the RESPONDER
        f.write(f"{T0 + 9 * 3600 + 9}\tC2\t203.0.113.7\t192.168.1.10\t1.0\t40\t4000\n")
        # transit: neither side local -> skipped
        f.write(f"{T0 + 9 * 3600 + 11}\tC3\t198.51.100.1\t198.51.100.2\t1.0\t1\t1\n")
    with open(os.path.join(a, "ssl.log"), "w") as f:
        f.write(hdr.format("ts\tuid\tserver_name"))
        f.write(f"{T0 + 9 * 3600 + 5}\tC1\tgithub.com\n")
    with open(os.path.join(a, "dns.log"), "w") as f:
        f.write(hdr.format("ts\tquery\tanswers"))
        f.write(f"{T0 + 9 * 3600}\tapi.telegram.org\t149.154.167.220,2001:67c:4e8:f004::9\n")
    with open(os.path.join(b, "conn.log"), "w") as f:
        f.write(hdr.format("ts\tuid\tid.orig_h\tid.resp_h\tduration\torig_bytes\tresp_bytes"))
        # no SNI; named by the DNS answer seen in the PREVIOUS folder
        f.write(f"{T0 + 10 * 3600 + 5}\tC9\t192.168.1.10\t149.154.167.220\t1.0\t300\t300\n")
        # a global IPv6 host is only local when the caller says so
        f.write(f"{T0 + 10 * 3600 + 6}\tC8\t2401:db00::5\t142.250.1.1\t1.0\t1\t1\n")


def test_zeek(tmp):
    print("\nZeek import")
    root = os.path.join(tmp, "zeek")
    _zeek_fixture(root)
    recs = list(HW.records_from_zeek(root))
    check("transit and unknown-global rows skipped", len(recs) == 3, str(len(recs)))
    inbound = [r for r in recs if r.peer == "203.0.113.7"]
    check("inbound conn: host is the local responder, bytes swapped",
          len(inbound) == 1 and inbound[0].host == "192.168.1.10" and inbound[0].up == 4000 and inbound[0].down == 40)
    named = [r for r in recs if r.peer == "149.154.167.220"]
    check("DNS answer names a peer in a later folder", named and named[0].name == "api.telegram.org")
    recs6 = list(HW.records_from_zeek(root, local_ips=["2401:db00::5"]))
    check("--local-ip makes a global IPv6 address a device", any(r.host == "2401:db00::5" for r in recs6))

    st = HW.CorpusStore(os.path.join(tmp, "c.sqlite"), tz_offset=IST)
    res = HW.ingest(HW.records_from_zeek(root), st)
    s = st.summary()
    check("ingest writes windows", res["windows_written"] == s["windows"] > 0, str(res))
    check("tz stored with the corpus", HW.CorpusStore(os.path.join(tmp, "c.sqlite")).tz == IST)
    cats = s["categories"]
    check("Messaging_API window from the DNS-named peer", cats.get("Messaging_API") == 1, str(cats))


def test_store_and_samples(tmp):
    print("\ncorpus store, flagged exclusion, cohort isolation")
    rng = np.random.default_rng(0)
    a = HW.CorpusStore(os.path.join(tmp, "a.sqlite"), tz_offset=0)
    b = HW.CorpusStore(os.path.join(tmp, "b.sqlite"), tz_offset=0)
    day = 20000 * 24
    rows_a = [(f"h{i}", day + w, 4, 3, rng.normal(size=10).astype(np.float32)) for i in range(3) for w in range(24)]
    rows_b = [("x", day + w, 4, 3, np.full(10, 100.0, np.float32)) for w in range(24)]
    a.put(rows_a, flagged=[("h0", day + 5)])
    b.put(rows_b)
    check("flagged window stored", a.summary()["flagged_windows"] == 1)
    check("flagged window left out of rows()", len(a.rows()) == len(rows_a) - 1)
    S = HW.build_samples([(a, "base:"), (b, "live:")])
    check("one sample per host-day", len(S["host_day"]) == 4, str(len(S["host_day"])))
    i = S["host_day"].index(("base:h1", 20000))
    check("cohort of a baseline host ignores the other network (values of 100)",
          float(np.abs(S["cohort"][i]).max()) < 50)
    j = S["host_day"].index(("live:x", 20000))
    check("a lone host's cohort is empty", float(np.abs(S["cohort"][j]).max()) == 0.0)
    before = HW.build_samples([(b, "live:")], before_lhour={"live:": day + 12})
    check("before_lhour drops the incomplete day's later hours",
          int(before["mask"][0][:, 4].sum()) == 12)


def _office_day(rng, host, day_lh, chain=False):
    rows = []
    for w in range(24):
        if 9 <= w <= 18:
            for cat in ("Browse", "Messaging_API", "Sync"):
                n = int(rng.integers(20, 40))
                iat = rng.lognormal(np.log(60), 1.0, n)
                rows.append((host, day_lh + w, CAT_INDEX[cat], n,
                             _edge_row(None, n, n * 3e3, n * 5e4, iat, 0.3, 5.0)))
    if chain:
        w = 14
        for cat, up in (("Recon_API", 1e3), ("Code_Repo_Paste", 2e3), ("Cloud_Storage", 5e7)):
            iat = np.full(40, 60.0)                      # machine-regular check-ins
            rows.append((host, day_lh + w, CAT_INDEX[cat], 40, _edge_row(None, 40, up, 500, iat, 1.0, 0.5)))
    return rows


def test_train_and_score(tmp):
    print("\ntrain -> save -> load -> score (needs torch)")
    try:
        import torch  # noqa: F401
    except ImportError:
        print("  [skip] torch not installed")
        return
    import inspector_live as IL
    rng = np.random.default_rng(1)
    base = HW.CorpusStore(os.path.join(tmp, "base.sqlite"), tz_offset=0)
    live = HW.CorpusStore(os.path.join(tmp, "state", "live_corpus.sqlite"), tz_offset=0)
    d0 = 20000
    rows = []
    for d in range(12):
        for h in range(5):
            rows += _office_day(rng, f"dev-{h:02d}", (d0 + d) * 24)
    base.put(rows)
    live.put(_office_day(rng, "192.168.1.50", (d0 + 12) * 24))
    b = IL.train_bundle(base, live, epochs_teacher=4, epochs_student=4, live_days=60,
                        log=lambda t: None, exclude_today=False)
    check("trained on baseline + live", b["meta"]["baseline_host_days"] == 60 and b["meta"]["live_host_days"] == 1,
          str(b["meta"]))
    IL.save_bundle(b, os.path.join(tmp, "state"))
    lb = IL.load_bundle(os.path.join(tmp, "state"))
    check("bundle survives save/load", lb is not None and abs(lb["thr"] - b["thr"]) < 1e-9)

    day = (d0 + 30) * 24
    hosts = ["dev-00", "dev-01", "dev-02", "dev-03", "victim"]
    rows = []
    for h in hosts:
        rows += _office_day(rng, h, day, chain=(h == "victim"))
    rows = [r[:5] for r in rows if r[1] % 24 <= 14]
    scores, esc, errs, cats, _s, _i = IL.score_hour(lb, hosts, rows, 14, budget_k=1)
    check("the Sentry escalates the chain host", esc == ["victim"], f"{esc} {scores}")
    check("the Inspector flags it", errs.get("victim", 0) >= lb["thr"], f"err {errs} thr {lb['thr']:.3f}")
    check("verdict carries the chain categories",
          {"Recon_API", "Code_Repo_Paste", "Cloud_Storage"} <= set(cats["victim"]))
    rows_norm = [r for r in rows if r[0] != "victim"]
    _sc, esc2, errs2, _c, _a, _b = IL.score_hour(lb, hosts[:4], rows_norm, 14, budget_k=1)
    check("an ordinary office hour is not flagged", all(e < lb["thr"] for e in errs2.values()), str(errs2))


def main():
    tmp = tempfile.mkdtemp()
    try:
        test_time()
        test_aggregator()
        test_zeek(tmp)
        test_store_and_samples(tmp)
        test_train_and_score(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if FAIL:
        print(f"FAILED {len(FAIL)}: {FAIL}")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
