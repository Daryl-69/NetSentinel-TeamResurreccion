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


def test_npz_and_corpus_exchange(tmp):
    print("\npcap_to_tensor npz import, corpus export / merge")
    E = np.zeros((1, 2, 24, 9, 10), np.float32); M = np.zeros((1, 2, 24, 9), np.float32)
    E[0, 1, 9, 4, 0] = np.log1p(12.0); M[0, 1, 9, 4] = 1
    good = os.path.join(tmp, "good.npz")
    np.savez(good, edges=E, mask=M, hosts=np.array(["192.168.1.7"]), span_hours=48.0,
             lhour0=20000 * 24, tz_offset=IST, hourly_flows=True)
    rows, tz = HW.rows_from_npz(good)
    check("npz window lands on its clock hour", rows and rows[0][1] == 20001 * 24 + 9 and tz == IST, str(rows[:1]))
    check("npz connection count recovered", rows and abs(rows[0][3] - 12.0) < 1e-3)
    legacy = os.path.join(tmp, "legacy.npz")
    np.savez(legacy, edges=E, mask=M, hosts=np.array(["192.168.1.7"]), span_hours=48.0)
    try:
        HW.rows_from_npz(legacy); refused = False
    except ValueError:
        refused = True
    check("old whole-capture npz refused", refused)
    a = HW.CorpusStore(os.path.join(tmp, "siteA.sqlite"), tz_offset=IST)
    a.put([("192.168.1.10", 20000 * 24 + 9, 4, 5, np.ones(10, np.float32))], flagged=[])
    a.put([("192.168.1.11", 20000 * 24 + 9, 4, 5, np.ones(10, np.float32))], flagged=[("192.168.1.11", 20000 * 24 + 9)])
    s = HW.export_corpus(a, os.path.join(tmp, "export.sqlite"), "siteA")
    check("export leaves out flagged windows and real addresses",
          s["windows"] == 1 and HW.CorpusStore(os.path.join(tmp, "export.sqlite")).rows()[0][0] == "siteA-01")
    dst = HW.CorpusStore(os.path.join(tmp, "pooled.sqlite"), tz_offset=IST)
    dst.put([("siteA-01", 20000 * 24 + 9, 4, 5, np.zeros(10, np.float32))])
    HW.merge_corpus(os.path.join(tmp, "export.sqlite"), dst, "export:")
    check("merged hosts are prefixed, never collide", dst.summary()["hosts"] == 2)


def test_warm_start_and_calibration(tmp):
    print("\nshipped model: tolerant load, calibration, warm start (needs torch)")
    try:
        import torch  # noqa: F401
    except ImportError:
        print("  [skip] torch not installed")
        return
    import types
    import inspector_live as IL
    rng = np.random.default_rng(2)
    base = HW.CorpusStore(os.path.join(tmp, "wbase.sqlite"), tz_offset=0)
    rows = []
    for d in range(6):
        for h in range(3):
            rows += _office_day(rng, f"dev-{h}", (20000 + d) * 24)
    base.put(rows)
    empty = HW.CorpusStore(os.path.join(tmp, "wlive.sqlite"), tz_offset=0)
    b = IL.train_bundle(base, empty, 2, 2, None, exclude_today=False, log=lambda t: None)
    shipped_dir = os.path.join(tmp, "shipped")
    IL.publish_bundle(b, shipped_dir)
    # strip the metadata the service expects, like a model trained by another script
    import torch as _t
    ck = _t.load(os.path.join(shipped_dir, "inspector_baseline.pt"), weights_only=False)
    ck["meta"] = {"source": "own_corpus.npz", "hosts": 3}
    _t.save(ck, os.path.join(shipped_dir, "inspector_baseline.pt"))
    lb = IL.load_bundle(os.path.join(tmp, "nostate"), shipped_dir)
    check("model with foreign metadata loads", lb is not None and lb["meta"]["shipped"]
          and lb["meta"]["live_host_days"] == 0 and "params" in lb["meta"])

    a = types.SimpleNamespace(state=os.path.join(tmp, "svc"), baseline=os.path.join(tmp, "none.sqlite"),
                              calibrate_hours=6, calibrate_min_hours_of_day=3, budget=0.05)
    svc = IL.Service.__new__(IL.Service)
    svc.a, svc.hosts, svc.own_ips, svc.meta_version = a, [], set(), 0
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        svc._set_bundle(lb)
        check("shipped model starts in calibration", svc.calibrating)
        svc._calibrate([1.0, 1.1], 3); svc._calibrate([1.2, 9.0], 3); svc._calibrate([1.3, 1.4], 3)
        check("needs spread over hours of the day, not just a count", svc.calibrating)
        svc._calibrate([1.0], 10); svc._calibrate([1.1], 15)
    check("calibration finishes and raises the threshold to this network's 99th pct",
          not svc.calibrating and lb["thr"] >= lb["thr_trained"] and lb["thr"] > 8.0, f"{lb['thr']:.2f}")
    with contextlib.redirect_stdout(io.StringIO()):
        svc2 = IL.Service.__new__(IL.Service); svc2.a, svc2.hosts, svc2.own_ips, svc2.meta_version = a, [], set(), 0
        svc2._set_bundle(IL.load_bundle(os.path.join(tmp, "nostate"), shipped_dir))
    check("calibration survives a restart", not svc2.calibrating)

    live = HW.CorpusStore(os.path.join(tmp, "wlive2.sqlite"), tz_offset=0)
    live.put(_office_day(rng, "192.168.1.50", (20010) * 24) + _office_day(rng, "192.168.1.50", (20011) * 24))
    w = IL.train_bundle(None, live, 2, 2, None, exclude_today=False, init=lb, log=lambda t: None)
    same = all(torch.equal(p1, p2) for p1, p2 in zip(w["inspector"].state_dict().values(),
                                                     lb["inspector"].state_dict().values()))
    check("warm start fine-tunes the shipped weights (and changes them)",
          w["meta"]["warm_start_from"] == lb["meta"]["source"] and not same)


def main():
    tmp = tempfile.mkdtemp()
    try:
        test_time()
        test_aggregator()
        test_zeek(tmp)
        test_store_and_samples(tmp)
        test_train_and_score(tmp)
        test_npz_and_corpus_exchange(tmp)
        test_warm_start_and_calibration(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if FAIL:
        print(f"FAILED {len(FAIL)}: {FAIL}")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
