#!/usr/bin/env python3
"""Self-test for lanl_loader on a synthetic cyber1-format fixture.

Run:  python test_lanl_loader.py
Exits non-zero on any failure. This exists because every prior loader in this
repo shipped with a silent parsing bug that produced a confident wrong number.
"""
from __future__ import annotations

import gzip, os, shutil, sys, tempfile
import numpy as np

from netsentinel_v2 import lanl_loader as L

FAIL = []


def check(name, cond, detail=""):
    print(f"  [{'ok ' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    if not cond:
        FAIL.append(name)


# ---------------------------------------------------------------- unit tests
def test_classify():
    print("\nresolver / direction")
    hi, vhi = 8.0, 64.0
    # the dataset's OWN example row: service port is on the SOURCE side
    check("LANL example row 389->N10451 = Directory",
          L.classify("389", "N10451", 3, hi, vhi) == "Directory",
          L.classify("389", "N10451", 3, hi, vhi))
    check("SMB client N2414->445 = FileShare",
          L.classify("N2414", "445", 200, hi, vhi) == "FileShare")
    check("Kerberos reply 88->N7789 = Directory",
          L.classify("88", "N7789", 3, hi, vhi) == "Directory")
    check("RDP = RemoteAccess", L.classify("N99", "3389", 5, hi, vhi) == "RemoteAccess")
    check("both ephemeral + low fan-in = Workstation",
          L.classify("N1", "N2", 1, hi, vhi) == "Workstation")
    check("both ephemeral + huge fan-in = Infra",
          L.classify("N1", "N2", 900, hi, vhi) == "Infra")
    check("numeric unmapped port + mid fan-in = Unknown",
          L.classify("N1", "9999", 20, hi, vhi) == "Unknown")
    # Both sides numeric is rare and genuinely ambiguous; min() is the rule,
    # so 445 vs 1521 resolves to FileShare. Documented, not accidental.
    check("both-numeric resolves by min()",
          L.classify("445", "1521", 5, hi, vhi) == "FileShare",
          L.classify("445", "1521", 5, hi, vhi))

    ps, pd = L._port_num("N10451"), L._port_num("389")
    check("_port_num: N#### is ephemeral", ps is None)
    check("_port_num: 389 is numeric", pd == 389)


# ---------------------------------------------------------------- fixture
def build_fixture(root, days=4):
    """A tiny network: 1 DC, 1 file server, 12 workstations, 1 beaconing host."""
    rng = np.random.default_rng(7)
    rows = []
    DC, FS = "C1", "C2"
    wks = [f"C{i}" for i in range(10, 22)]
    beacon = "C10"
    for d in range(days):
        base = d * 86400
        for h in wks:
            for hour in range(8, 18):
                t0 = base + hour * 3600
                # kerberos to the DC (service port on the DST side)
                for _ in range(rng.integers(2, 6)):
                    t = t0 + int(rng.integers(0, 3600))
                    rows.append((t, 1, h, f"N{rng.integers(1000, 60000)}",
                                 DC, "88", 6, 5, int(rng.integers(200, 4000))))
                # SMB to the file server
                for _ in range(rng.integers(1, 4)):
                    t = t0 + int(rng.integers(0, 3600))
                    rows.append((t, 3, h, f"N{rng.integers(1000, 60000)}",
                                 FS, "445", 6, 30, int(rng.integers(1e4, 1e6))))
        # the file server itself talks to the DC a little -> it HAS client
        # traffic, but far too little to rank. It is a red-team destination,
        # so the loader must force-include it.
        for hour in (9, 13):
            rows.append((base + hour * 3600 + 5, 1, FS,
                         f"N{rng.integers(1000, 60000)}", DC, "88", 6, 5, 700))
        # a DC reply logged with the service port on the SOURCE side
        for hour in range(8, 18):
            t = base + hour * 3600 + 17
            rows.append((t, 0, DC, "389", wks[0], f"N{rng.integers(1000, 60000)}",
                         6, 10, 5323))
        # the beacon: fixed 300s period, jittered +/-10% -> UNIFORM IATs
        for k in range(0, 86400 // 300):
            t = base + int(k * 300 + rng.uniform(-30, 30))
            rows.append((t, 1, beacon, f"N{rng.integers(1000, 60000)}",
                         "C99", "443", 6, 4, 900))
    rows.sort(key=lambda r: r[0])
    rows = [(max(1, r[0]),) + r[1:] for r in rows]

    os.makedirs(root, exist_ok=True)
    with gzip.open(os.path.join(root, "flows.txt.gz"), "wt") as f:
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")
    # red team on day 2, one lateral hop wks[1] -> FS
    with gzip.open(os.path.join(root, "redteam.txt.gz"), "wt") as f:
        f.write(f"{2*86400 + 10*3600},U66@DOM1,{wks[1]},{FS}\n")
    return dict(dc=DC, fs=FS, wks=wks, beacon=beacon, days=days)


def test_load():
    print("\nend-to-end load")
    root = tempfile.mkdtemp(prefix="lanlfix_")
    try:
        fx = build_fixture(root)
        # max_hosts=12 keeps exactly the 12 workstations by rank; the file
        # server must arrive only via red-team force-inclusion.
        # novelty=False: this test asserts the ORIGINAL behaviour, where the
        # two uncomputable slots stay at exact zero. The novelty variant has
        # its own test below.
        d = L.load_lanl(root, max_hosts=12, days=fx["days"],
                        profile_rows=None, novelty=False, verbose=True)
        E, M = d["edges"], d["mask"]
        H, D, W, C, F = E.shape
        check("shape (H,D,24,9,10)", (D, W, C, F) == (fx["days"], 24, 9, 10),
              str(E.shape))
        check("mask non-empty", M.sum() > 0, f"{M.sum():.0f} edges")
        check("no NaN/inf", np.isfinite(E).all())

        names = list(d["hostnames"])
        cc = d["category_counts"]
        print("     categories:", {k: v for k, v in cc.items() if v})
        check("Directory present", cc["Directory"] > 0)
        check("FileShare present", cc["FileShare"] > 0)
        check("WebProxy present (beacon)", cc["WebProxy"] > 0)
        check("not everything collapsed into one class",
              sum(1 for v in cc.values() if v) >= 3,
              f"{sum(1 for v in cc.values() if v)} classes used")

        # direction: the DC's 389->N#### reply must be attributed to the
        # WORKSTATION (ephemeral side), not to the DC.
        check("workstations are kept as hosts", fx["wks"][0] in names)

        # unavailable features are exactly zero
        for fi in L.UNAVAILABLE_FEATURES:
            check(f"feature {fi} is all-zero", np.abs(E[..., fi]).max() == 0.0)
        check("feature_available flags match",
              [i for i, ok in enumerate(d["feature_available"]) if not ok]
              == list(L.UNAVAILABLE_FEATURES))

        # the beacon must look uniform (low KS-vs-uniform) on its WebProxy edge
        bi = names.index(fx["beacon"]) if fx["beacon"] in names else None
        check("beacon host retained", bi is not None)
        if bi is not None:
            wp = L.LCAT["WebProxy"]
            live = M[bi, :, :, wp] > 0
            ksu = E[bi, :, :, wp, 5][live]
            ksv = E[bi, :, :, wp, 6][live]
            check("beacon: KS-vs-uniform < KS-vs-exponential",
                  ksu.mean() < ksv.mean(),
                  f"ks_u={ksu.mean():.3f} ks_e={ksv.mean():.3f}")

        # red team
        A = d["is_attack_day"]
        check("red-team event matched a kept host", d["redteam_matched"] == 1)
        check("attack day is day 2", A.any(0)[2] and not A.any(0)[0])
        check("red-team destination force-included",
              d["redteam_hosts_forced"] == 1 and fx["fs"] in names,
              f"forced={d['redteam_hosts_forced']}")
        check("BOTH endpoints marked", A[:, 2].sum() == 2,
              f"{int(A[:, 2].sum())} hosts flagged on day 2")
        check("source and destination both counted",
              d["redteam_sources_modelled"] == 1 and d["redteam_dests_modelled"] == 1)
        check("is_attack_window is one window, not the day",
              d["is_attack_window"][:, 2].sum() == 2
              and d["is_attack_window"][:, 2].any(0).sum() == 1)

        print("\n" + L.summarise(d))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def build_lateral_fixture(root, days=8, attack_day=6):
    """A network where the ONLY thing distinguishing the attack is novelty.

    Volume, timing and duration on the attack day are drawn from exactly the
    same distributions as every other day. What changes is WHO: the compromised
    host suddenly reaches file servers and a jump box it has never touched.
    A volume/timing model must score ~0.5 here. A novelty feature must not.
    This is the only kind of fixture that can tell those two apart.
    """
    rng = np.random.default_rng(11)
    rows = []
    DC = "C1"
    servers = [f"S{i}" for i in range(2, 14)]      # 12 file servers
    wks = [f"C{i}" for i in range(10, 40)]         # 30 workstations
    victim = wks[0]
    # every workstation has a small, STABLE set of servers it uses
    home = {h: list(rng.choice(servers, size=2, replace=False)) for h in wks}

    def day_traffic(h, base, srv_pool):
        for hour in range(8, 18):
            t0 = base + hour * 3600
            for _ in range(int(rng.integers(2, 6))):     # Directory
                rows.append((t0 + int(rng.integers(0, 3600)), 1, h,
                             f"N{rng.integers(1000, 60000)}", DC, "88", 6, 5,
                             int(rng.integers(200, 4000))))
            for _ in range(int(rng.integers(2, 5))):     # FileShare
                s = srv_pool[int(rng.integers(0, len(srv_pool)))]
                rows.append((t0 + int(rng.integers(0, 3600)), 3, h,
                             f"N{rng.integers(1000, 60000)}", s, "445", 6, 30,
                             int(rng.integers(1e4, 1e6))))

    for d in range(days):
        base = d * 86400
        for h in wks:
            pool = home[h]
            if h == victim and d == attack_day:
                # SAME flow count, SAME bytes, SAME timing -- new peers only.
                pool = [s for s in servers if s not in home[h]][:6]
            day_traffic(h, base, pool)
        if victim and d == attack_day:                   # one new service class
            rows.append((base + 11 * 3600 + 90, 2, victim,
                         f"N{rng.integers(1000, 60000)}", "S2", "3389", 6, 20,
                         50000))
    rows.sort(key=lambda r: r[0])
    rows = [(max(1, r[0]),) + r[1:] for r in rows]
    os.makedirs(root, exist_ok=True)
    with gzip.open(os.path.join(root, "flows.txt.gz"), "wt") as f:
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")
    with gzip.open(os.path.join(root, "redteam.txt.gz"), "wt") as f:
        f.write(f"{attack_day*86400 + 11*3600},U9@DOM1,{victim},S2\n")
    return dict(victim=victim, attack_day=attack_day, days=days)


def _within_host_auc(err, atk, live):
    """Same statistic train_real.py reports, computed here on one host."""
    from run_experiment import roc_auc
    s, y = err[live], atk[live]
    if y.sum() == 0 or (~y).sum() < 3:
        return float("nan")
    return roc_auc(s, y)


def test_novelty_features():
    """The decisive test: does the novelty signal exist, and is it causal?"""
    print("\nnovelty features")
    root = tempfile.mkdtemp(prefix="lanlnov_")
    try:
        fx = build_lateral_fixture(root)
        got = {}
        for nov in (False, True):
            d = L.load_lanl(root, max_hosts=40, days=fx["days"],
                            profile_rows=None, tensor_cache=None,
                            novelty=nov, verbose=False)
            got[nov] = d

        off, on = got[False], got[True]
        names_on = on["feature_names"]
        check("slot 2 renamed with novelty on",
              names_on[2] == "new_peer_ratio", names_on[2])
        check("slot 3 renamed with novelty on",
              names_on[3] == "new_service_flag", names_on[3])
        check("slots stay zero with novelty off",
              np.abs(off["edges"][..., 2]).max() == 0
              and np.abs(off["edges"][..., 3]).max() == 0)
        check("slots are non-zero with novelty on",
              np.abs(on["edges"][..., 2]).max() > 0
              and np.abs(on["edges"][..., 3]).max() > 0)
        check("every other feature is byte-identical",
              np.array_equal(np.delete(off["edges"], [2, 3], axis=-1),
                             np.delete(on["edges"], [2, 3], axis=-1)),
              "novelty must not perturb volume/timing")
        check("new_peer_ratio stays in [0,1]",
              0.0 <= on["edges"][..., 2].min() and on["edges"][..., 2].max() <= 1.0)
        check("feature_available all True with novelty on",
              all(on["feature_available"]))

        # causality: novelty must be highest on day 0 and decay, never rise
        # because of something that happens later.
        M = on["mask"]; E = on["edges"]
        per_day = [float(E[:, d, :, :, 2][M[:, d] > 0].mean())
                   for d in range(fx["days"])]
        check("novelty decays after the warm-up day",
              per_day[0] > per_day[3],
              " ".join(f"{v:.2f}" for v in per_day))

        # the actual question
        names = list(on["hostnames"])
        vi = names.index(fx["victim"])
        ad = fx["attack_day"]
        res = {}
        for tag, d in (("off", off), ("on", on)):
            Ev, Mv = d["edges"][vi], d["mask"][vi]        # (D,W,C,F) (D,W,C)
            Dn, Wn, Cn, Fn = Ev.shape
            live = (Mv.sum(-1) > 0).reshape(-1)               # (D*W,)
            atk = np.zeros((Dn, Wn), dtype=bool); atk[ad] = True
            atk = (atk & (Mv.sum(-1) > 0)).reshape(-1)
            # Proxy for the Inspector: per-window distance from this host's own
            # median window. Model-free, and enough to answer the only question
            # that matters here -- is the SIGNAL present in the tensor at all?
            # Standardise PER FEATURE across present edges exactly as
            # train.standardise() does. Skipping this would let log_bytes
            # (~13) drown a 0-1 novelty feature and the test would "prove"
            # the feature is useless when only the scaling was wrong.
            allE, allM = d["edges"], d["mask"]
            flatv = allE[allM > 0]
            mu, sdv = flatv.mean(0), flatv.std(0) + 1e-6
            Z = ((Ev - mu) / sdv) * (Mv[..., None] > 0)
            Xw = Z.reshape(Dn * Wn, Cn * Fn)
            med = np.median(Xw[live], axis=0)
            sc = np.abs(Xw - med).mean(-1)
            res[tag] = _within_host_auc(sc, atk, live)
        print(f"     within-host AUC on the victim: "
              f"novelty OFF {res['off']:.3f}   ON {res['on']:.3f}")
        check("volume/timing alone cannot see this attack",
              res["off"] < 0.75, f"{res['off']:.3f}")
        check("novelty features CAN see it",
              res["on"] > res["off"] + 0.15,
              f"{res['off']:.3f} -> {res['on']:.3f}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cache_keyed_on_novelty():
    """A stale cache that ignores the novelty flag would silently 'reproduce'
    a result it never computed. This is the check for that."""
    print("\ncache key")
    root = tempfile.mkdtemp(prefix="lanlck_")
    try:
        build_fixture(root, days=4)
        a1 = L.load_lanl(root, max_hosts=12, days=4, profile_rows=None,
                         tensor_cache=root, novelty=True, verbose=False)
        b1 = L.load_lanl(root, max_hosts=12, days=4, profile_rows=None,
                         tensor_cache=root, novelty=False, verbose=False)
        a2 = L.load_lanl(root, max_hosts=12, days=4, profile_rows=None,
                         tensor_cache=root, novelty=True, verbose=False)
        check("novelty=False is not served the novelty=True tensors",
              np.abs(b1["edges"][..., 2]).max() == 0)
        check("cached reload reproduces the same tensors exactly",
              np.array_equal(a1["edges"], a2["edges"]))
        files = sorted(f for f in os.listdir(root) if f.endswith(".npz"))
        check("one cache file per variant", len(files) == 2, str(files))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_pipeline_compat():
    """The whole point: the existing training code must consume this untouched."""
    print("\ndownstream compatibility")
    from netsentinel_v2 import train as T
    root = tempfile.mkdtemp(prefix="lanlfix2_")
    try:
        build_fixture(root, days=4)
        d = L.load_lanl(root, max_hosts=16, days=4, profile_rows=None,
                        verbose=False)
        E, M = d["edges"], d["mask"]
        Co = T.compute_cohort(E, M)
        check("compute_cohort shape", Co.shape == E.shape)
        flat = lambda X: X[:, :2].reshape(-1, *X.shape[2:])
        Ec, Mc, Cc = flat(E), flat(M), flat(Co)
        Ec, mu, sd = T.standardise(Ec, Mc)
        check("standardise finite", np.isfinite(Ec).all())
        insp = T.train_inspector(Ec, Mc, Cc, epochs=1, seed=0)
        Z, err = T.inspector_forward(insp, Ec, Mc, Cc)
        check("inspector forward finite", np.isfinite(err).all())
        check("no sentinel leak (err < 1e6)", float(err.max()) < 1e6,
              f"max err {err.max():.3e}")
        sen = T.train_sentry(Ec, Mc, Z, err, epochs=1, seed=0)
        Zs = T.sentry_forward(sen, Ec, Mc)
        check("sentry forward finite", np.isfinite(Zs).all())
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_truncated_gzip():
    """A half-downloaded flows.txt.gz must degrade, not crash.

    This is the normal failure for a 12 GB file off the LANL server, and the
    crash lands ~40 minutes into a run with all the read data still good.
    """
    print("\ntruncated download")
    root = tempfile.mkdtemp(prefix="lanltrunc_")
    try:
        build_fixture(root, days=6)
        path = os.path.join(root, "flows.txt.gz")
        full = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(int(full * 0.6))
        with open(path, "wb") as f:            # chop off the end-of-stream marker
            f.write(head)
        check("fixture really is truncated now", os.path.getsize(path) < full)

        d = L.load_lanl(root, max_hosts=12, days=6, profile_rows=None,
                        tensor_cache=None, verbose=True)
        check("did not raise", True)
        check("reports truncation", d["file_truncated"] is True,
              str(d["truncation_detail"])[:60])
        check("still produced edges", d["mask"].sum() > 0,
              f"{d['mask'].sum():.0f} edges")
        check("no NaN/inf after a partial read", np.isfinite(d["edges"]).all())
        check("names the last usable day", 0 <= d["last_usable_day"] < 6,
              f"day {d['last_usable_day']}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    test_classify()
    test_load()
    test_truncated_gzip()
    test_novelty_features()
    test_cache_keyed_on_novelty()
    test_pipeline_compat()
    print("\n" + "=" * 60)
    if FAIL:
        print(f"{len(FAIL)} FAILED: {FAIL}")
        sys.exit(1)
    print("all checks passed")
