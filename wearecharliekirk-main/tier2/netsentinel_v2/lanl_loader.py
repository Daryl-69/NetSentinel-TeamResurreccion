"""LANL cyber1 -> the same (host, day, window, category, feature) tensors that
`synth.generate()` and `zeek_loader.load_dir()` produce.

Dataset: "Comprehensive, Multi-Source Cyber-Security Events" (Kent, 2015),
58 days of a real enterprise network, ~17,700 computers, with a
RED-TEAM GROUND TRUTH file. That last part is why this dataset matters here:
it is the only thing available to us that turns `recall_attack` from an
indicative synthetic number into a real one.

    flows.txt.gz    time,duration,src,src_port,dst,dst_port,protocol,packets,bytes
    redteam.txt.gz  time,user@domain,src_computer,dst_computer

--------------------------------------------------------------------------
WHAT THIS LOADER DOES DIFFERENTLY FROM THE OBVIOUS IMPLEMENTATION, AND WHY
--------------------------------------------------------------------------
1. It does NOT key the resolver on the destination port. LANL anonymises
   ephemeral ports as `N#####` and leaves well-known ports numeric, but it
   does NOT normalise flow direction. The dataset's own example row

       1,0,C1065,389,C3799,N10451,6,10,5323

   has the service port (389, LDAP) on the SOURCE side. A dst-port resolver
   calls that flow Unknown and gets the direction backwards. We take the
   service port as `min(numeric ports)` and treat the endpoint holding the
   EPHEMERAL port as the client -- the host whose behaviour we are modelling.

2. It uses an INTERNAL asset taxonomy, not the LOTS taxonomy. LANL is an
   all-internal enterprise network: there are no trusted external SaaS
   destinations to categorise, so `Recon_API / Code_Repo_Paste / ...` would
   collapse to ~100% `Internal` and carry no information. The nine internal
   classes below occupy the same nine tensor slots, so models.py, baseline.py
   and train.py are untouched.

3. `egress_asymmetry` and `log_bytes_down` cannot be computed here: cyber1
   flows carry ONE byte count, not a directional pair. (The 2017 "Unified Host
   and Network" release does have SrcBytes/DstBytes -- and no red-team labels.
   Labels or directionality; not both.) With `novelty=False` they are written
   as exact zeros and reported as unavailable.

   With `novelty=True` (the default) those two dead slots instead carry
   `new_peer_ratio` and `new_service_flag` -- see NOVELTY_FEATURES below. The
   first run of this loader without them scored a within-host AUC of
   0.526 +/- 0.308 against the real red team, i.e. chance: volume and timing
   do not distinguish a credential-based hop from normal admin traffic. Run
   both ways and compare; `--no-novelty` reproduces the original.

4. Fan-in thresholds are MEASURED, not guessed. A first streaming pass builds
   the distinct-source-count distribution over destinations and takes its
   p90 / p99; hard-coded "> 500 clients = server" numbers are meaningless on
   a network whose scale you have not looked at.

5. Red-team rows are AUTHENTICATION events, not flows. They name a source and
   a destination computer. `label_policy` decides what gets marked, and the
   default is BOTH, not dst-only:

     "dst"  the host being broken into. Intuitive, and WRONG for this system:
            the behaviour NetSentinel models is a host's OUTBOUND traffic, so
            the row whose shape actually changes is the compromised SOURCE.
            Labelling only dst puts the positives on rows whose behaviour we
            never claimed would look different, and drives recall toward zero
            for reasons that have nothing to do with the detector.
     "src"  the beachhead making the hop. Matches what we detect, but its
            initial-compromise time is unknown, so early windows are
            mislabelled benign.
     "both" default. Union of the two. State it whenever you quote a number.

   Switch it and re-run before concluding anything from a low attack recall.

6. Host attribution follows the CLIENT, not `src_computer`. cyber1 does not
   normalise direction (see #1), so keying the host on column 2 mixes a
   workstation's Kerberos request and a DC's Kerberos reply into the same
   category on different rows, and fills the "busiest hosts" list with
   servers. We attribute each flow to the endpoint holding the ephemeral port.
"""

from __future__ import annotations

import gzip
import json
import os
import time
import zlib
from array import array
from collections import defaultdict

import numpy as np

from .categories import N_CATEGORIES, N_EDGE_FEATURES
from .synth import _edge_row, WINDOWS_PER_DAY

SECONDS_PER_DAY = 86400
WINDOW_SECONDS = SECONDS_PER_DAY // WINDOWS_PER_DAY          # 3600

# --------------------------------------------------------------------------
# Internal asset taxonomy. Exactly N_CATEGORIES entries so the tensor shape,
# the category embedding and every downstream model stay byte-identical.
# --------------------------------------------------------------------------
LANL_CATEGORIES = [
    "Directory",     # Kerberos / LDAP / GC        -> auth backbone
    "FileShare",     # SMB / NFS                   -> the lateral-movement road
    "RemoteAccess",  # RDP / SSH / WinRM / VNC     -> hands-on-keyboard
    "Mail",          # SMTP / IMAP / POP
    "WebProxy",      # HTTP(S) / proxy ports
    "Database",      # MSSQL / Oracle / MySQL / PG
    "Infra",         # DNS / NTP / SNMP / RPC / syslog
    "Workstation",   # peer-to-peer, both ports ephemeral, low fan-in
    "Unknown",       # numeric-but-unmapped service, or mid fan-in
]
assert len(LANL_CATEGORIES) == N_CATEGORIES, "taxonomy must fill the tensor"
LCAT = {c: i for i, c in enumerate(LANL_CATEGORIES)}

PORT_CLASS: dict[int, str] = {}
for _cls, _ports in {
    "Directory":    (88, 389, 464, 636, 749, 750, 3268, 3269),
    "FileShare":    (137, 138, 139, 445, 2049),
    "RemoteAccess": (22, 23, 1723, 3389, 5900, 5985, 5986),
    "Mail":         (25, 110, 143, 465, 587, 993, 995),
    "WebProxy":     (80, 443, 3128, 8000, 8080, 8443),
    "Database":     (1433, 1434, 1521, 3306, 5432, 27017, 50000),
    "Infra":        (53, 67, 68, 111, 123, 135, 161, 162, 514, 546, 547,
                     5353, 5355),
}.items():
    for _p in _ports:
        PORT_CLASS[_p] = _cls

# Feature-schema availability on this dataset (indices into EDGE_FEATURES).
#   2 = log_bytes_down, 3 = egress_asymmetry
# cyber1 logs ONE byte count, so both are uncomputable and would sit at exact
# zero -- two dead columns out of ten.
UNAVAILABLE_FEATURES = (2, 3)

# ...which is why we repurpose them, LANL-only, for the signal that actually
# describes lateral movement. Volume and timing cannot separate a red-team
# hop over Kerberos/SMB/RDP from an administrator's Tuesday: both are ordinary
# traffic to ordinary services. What differs is NOVELTY -- a host reaching a
# peer, or a service class, it has never reached before. That is the classic
# lateral-movement signature and this feature schema had no term for it.
#
# Both are measured against the host's ESTABLISHED PROFILE: the set of peers
# and service classes it was seen using during the commissioning period. The
# profile grows causally through commissioning (a peer counts as new only
# until the first window that uses it) and then FREEZES.
#
# Freezing matters. With an ever-growing prefix, a lateral hop is novel for
# exactly one window and ordinary from the second window onwards, so an attack
# spanning ten windows shows novelty in one of them and the metric is capped
# by construction. A frozen profile is also the operationally honest question
# -- "is this host doing something outside the profile we commissioned it
# with?" -- and it is what every per-host baseline in this codebase already
# assumes. It uses no future information: the profile is complete before the
# first evaluated window begins.
NOVELTY_FEATURES = {
    2: "new_peer_ratio",      # distinct peers never seen before / distinct peers
    3: "new_service_flag",    # 1.0 the first time this host uses this class
}
# Per-host peer memory. A pathological host talking to tens of thousands of
# peers would otherwise dominate memory; past the cap we STOP claiming novelty
# for that host (report 0.0) rather than inventing it, and count the hosts
# affected so the number is never silently wrong.
PEER_MEMORY_CAP = 8192

# Per-bucket timestamp retention. Beyond this we keep the HEAD of the window,
# which preserves periodicity exactly (what the KS/FFT features are for) at the
# cost of covering only part of a very busy hour. Reservoir sampling would be
# worse here: random thinning destroys a fixed-period beacon's signature.
TS_CAP = 4096


# ------------------------------------------------------------------ plumbing
def _open(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") \
        else open(path, "rt", errors="replace")


# A partially-downloaded .gz decompresses fine until it reaches the missing
# end-of-stream marker, then throws -- tens of minutes into the run, with
# everything read so far still perfectly good. The cyber1 files are ~12 GB and
# the LANL server drops connections, so this is the normal failure, not a rare
# one. Yield what is readable, report the cut, and let the caller decide.
_TRUNCATION_ERRORS = (EOFError, zlib.error, gzip.BadGzipFile, OSError)


class _Truncated(Exception):
    """Carries the row count at which a gzip stream ended early."""
    def __init__(self, rows, reason):
        super().__init__(reason)
        self.rows, self.reason = rows, reason


def _safe_lines(f, counter=None):
    """Iterate a possibly-truncated stream. Raises _Truncated when it ends
    early, after every complete line has already been yielded."""
    n = 0
    while True:
        try:
            line = f.readline()
        except _TRUNCATION_ERRORS as e:
            raise _Truncated(n, f"{type(e).__name__}: {e}") from None
        if not line:
            return
        n += 1
        yield line


def _port_num(p: str):
    """LANL keeps well-known ports numeric and anonymises ephemeral ones as
    N#####. `None` therefore means 'this side is the client'."""
    if not p or p[0] in "Nn":
        return None
    try:
        return int(p)
    except ValueError:
        return None


def find_lanl(root: str) -> dict:
    """Locate the two cyber1 files anywhere under `root`."""
    want = {"flows": ("flows.txt.gz", "flows.txt"),
            "redteam": ("redteam.txt.gz", "redteam.txt")}
    found: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        lower = {f.lower(): f for f in files}
        for key, names in want.items():
            if key in found:
                continue
            for n in names:
                if n in lower:
                    found[key] = os.path.join(dirpath, lower[n])
                    break
    return found


# --------------------------------------------------------------- first pass
def profile(flows_path: str, max_rows: int | None = 20_000_000,
            fanin_cap: int = 1024, progress_every: int = 5_000_000) -> dict:
    """Measure what we need before we can allocate anything.

    Returns per-host client-flow counts (to choose which hosts to keep) and
    the distinct-source fan-in per destination (to set the server thresholds
    from the data instead of from a guess).
    """
    ids: dict[str, int] = {}
    client_flows: dict[int, int] = defaultdict(int)
    fanin: dict[int, set] = defaultdict(set)
    n = 0
    cut = None
    t0 = time.time()
    with _open(flows_path) as f:
        try:
            for line in _safe_lines(f):
                n += 1
                if max_rows and n > max_rows:
                    break
                if progress_every and n % progress_every == 0:
                    rate = n / max(time.time() - t0, 1e-9)
                    print(f"    [profile] {n:,} rows  ({rate/1e6:.2f}M rows/s)",
                          flush=True)
                p = line.rstrip("\n").split(",")
                if len(p) < 9:
                    continue
                src, sp, dst, dp = p[2], p[3], p[4], p[5]
                si = ids.setdefault(src, len(ids))
                di = ids.setdefault(dst, len(ids))
                ps, pd = _port_num(sp), _port_num(dp)
                # client = ephemeral side; ambiguous cases keep logged direction
                if ps is not None and pd is None:
                    cli, peer = di, si
                else:
                    cli, peer = si, di
                client_flows[cli] += 1
                s = fanin[peer]
                if len(s) < fanin_cap:
                    s.add(cli)
        except _Truncated as e:
            cut = e.reason
            print(f"    [profile] !! gzip stream ends early at row {n:,} "
                  f"({cut}). Profiling what was readable.", flush=True)

    deg = np.array([len(v) for v in fanin.values()], dtype=np.float64)
    hi = float(np.percentile(deg, 90)) if deg.size else 8.0
    vhi = float(np.percentile(deg, 99)) if deg.size else 64.0
    if vhi <= hi:                      # degenerate on tiny fixtures
        vhi = hi + 1.0
    print(f"    [profile] {n:,} rows, {len(ids):,} computers, "
          f"fan-in p90={hi:.0f} p99={vhi:.0f} "
          f"(cap {fanin_cap}) in {time.time()-t0:.0f}s", flush=True)
    return dict(ids=ids, client_flows=dict(client_flows),
                fanin={k: len(v) for k, v in fanin.items()},
                fanin_p90=hi, fanin_p99=vhi, rows_profiled=n,
                truncated_at=(n if cut else None), truncation=cut)


def classify(src_port: str, dst_port: str, peer_fanin: int,
             hi: float, vhi: float) -> str:
    """Service port is min(numeric ports) -- NOT the destination port."""
    ps, pd = _port_num(src_port), _port_num(dst_port)
    cands = [p for p in (ps, pd) if p is not None]
    if cands:
        cls = PORT_CLASS.get(min(cands))
        if cls:
            return cls
    # No mapped service port. Fall back to how server-shaped the peer is.
    if peer_fanin >= vhi:
        return "Infra"
    if peer_fanin >= hi:
        return "Unknown"
    return "Workstation"


# ------------------------------------------------------------- red-team file
def load_redteam(path: str) -> list[tuple[int, str, str]]:
    out = []
    if not path or not os.path.exists(path):
        return out
    with _open(path) as f:
        for line in f:
            p = line.rstrip("\n").split(",")
            if len(p) < 4:
                continue
            try:
                out.append((int(p[0]), p[2], p[3]))
            except ValueError:
                continue
    return out


# -------------------------------------------------------------- second pass
def load_lanl(root: str, max_hosts: int = 800, days: int | None = None,
              profile_rows: int | None = None,
              cache: str | None = None, max_gb: float = 6.0,
              include_redteam_hosts: bool = True, label_policy: str = "both",
              tensor_cache: str | None = None, novelty: bool = True,
              novelty_baseline_days: int | None = None,
              progress_every: int = 5_000_000, verbose: bool = True) -> dict:
    """Build the tensors. Streams; day-by-day flush keeps memory bounded."""
    if label_policy not in ("both", "src", "dst"):
        raise ValueError("label_policy must be one of: both, src, dst")
    t0 = time.time()
    files = find_lanl(root)
    # flows.txt.gz is ~12 GB and is read by exactly two things: the pass-1
    # profile and the pass-2 tensor build. BOTH are cached. So a missing flows
    # file is only fatal if the cache that would have replaced it is also
    # missing -- checked at the point of use, not here. redteam.txt.gz is a
    # few KB, is NOT in either cache, and is what carries the attack labels.
    flows_path = files.get("flows")
    rt_path = files.get("redteam")
    if verbose:
        print(f"    flows  : {flows_path or 'absent -- caches must cover it'}")
        print(f"    redteam: {rt_path or 'MISSING -- no attack labels'}",
              flush=True)

    # ---- pass 1 (cached) ------------------------------------------------
    prof = None
    if cache and os.path.exists(cache):
        with open(cache) as f:
            raw = json.load(f)
        prof = dict(ids=raw["ids"],
                    client_flows={int(k): v for k, v in raw["client_flows"].items()},
                    fanin={int(k): v for k, v in raw["fanin"].items()},
                    fanin_p90=raw["fanin_p90"], fanin_p99=raw["fanin_p99"],
                    rows_profiled=raw["rows_profiled"],
                    truncation=raw.get("truncation"))
        if verbose:
            print(f"    [profile] loaded from {cache}", flush=True)
    if prof is None:
        if not flows_path:
            raise RuntimeError(
                f"no flows.txt(.gz) under {root} AND no usable profile cache "
                f"at {cache!r}. One of the two is required: either point "
                f"--data at the folder holding the LANL cyber1 files, or "
                f"supply the lanl_profile.json written by an earlier run.")
        prof = profile(flows_path, max_rows=profile_rows,
                       progress_every=progress_every)
        if cache:
            with open(cache, "w") as f:
                json.dump(dict(ids=prof["ids"],
                               client_flows={str(k): v for k, v in prof["client_flows"].items()},
                               fanin={str(k): v for k, v in prof["fanin"].items()},
                               fanin_p90=prof["fanin_p90"],
                               fanin_p99=prof["fanin_p99"],
                               rows_profiled=prof["rows_profiled"],
                               truncation=prof.get("truncation")), f)

    ids, fanin = prof["ids"], prof["fanin"]
    hi, vhi = prof["fanin_p90"], prof["fanin_p99"]
    name_of = {v: k for k, v in ids.items()}

    # ---- host selection --------------------------------------------------
    # Hosts are ranked by CLIENT-side flow count, because the thing we model
    # is "this host reached out to that class of service". A pure server is
    # therefore rarely a modelled host -- which matters, because red-team
    # lateral movement targets servers. So we also force-include any red-team
    # computer that has client-side traffic at all: evaluating attack recall
    # on a host set that happens to exclude the attacked hosts is worthless.
    rt = load_redteam(rt_path) if rt_path else []
    rt_names = {c for (_t, s, d_) in rt for c in (s, d_)}

    ranked = sorted(prof["client_flows"].items(), key=lambda kv: -kv[1])
    chosen = [g for g, _n in ranked[:max_hosts]]
    chosen_set = set(chosen)
    forced = 0
    if include_redteam_hosts:
        for name in sorted(rt_names):
            gid = ids.get(name)
            if gid is None or gid in chosen_set:
                continue
            if prof["client_flows"].get(gid, 0) <= 0:
                continue          # no client-side traffic: would be an empty row
            chosen.append(gid); chosen_set.add(gid); forced += 1
    keep = {gid: i for i, gid in enumerate(chosen)}
    hostnames = [name_of[g] for g in chosen]
    H = len(keep)
    if H == 0:
        raise RuntimeError("no client-side flows found; is this really cyber1?")
    if verbose and forced:
        print(f"    +{forced} red-team computer(s) force-included beyond the "
              f"top-{max_hosts} (they had client traffic but were not busy "
              f"enough to rank)", flush=True)

    D = days or 58
    gb = H * D * WINDOWS_PER_DAY * N_CATEGORIES * N_EDGE_FEATURES * 4 / 1e9
    total_gb = gb * 2.2 + gb * 0.1      # edges + cohort working copies + mask
    if verbose:
        print(f"    keeping {H} hosts x {D} days -> edges {gb:.2f} GB, "
              f"~{total_gb:.2f} GB peak with cohort", flush=True)
    if total_gb > max_gb:
        raise MemoryError(
            f"projected peak {total_gb:.1f} GB exceeds --max-gb {max_gb}. "
            f"Lower --max-hosts (currently {max_hosts}) or --days.")

    # ---- tensor cache ----------------------------------------------------
    # Pass 2 is the expensive part and does not depend on `label_policy`, so
    # re-running with a different labelling costs nothing after the first go.
    # The novelty flag changes the tensor contents, so it MUST be in the cache
    # key. Without it an A/B run silently reloads the other variant's tensors
    # and "reproduces" a result it never computed.
    # Default the profile window to the commissioning split train_real.py uses
    # (D // 2), so the frozen profile ends exactly where training data ends.
    nb_days = novelty_baseline_days if novelty_baseline_days is not None \
        else max(1, D // 2)
    cache_key = f"H{H}_D{D}_nov{int(novelty)}" + (f"_b{nb_days}" if novelty else "")
    tc = tensor_cache
    if tc and os.path.isdir(tc):
        tc = os.path.join(tc, f"lanl_tensors_{cache_key}.npz")
    E = M = None
    if tc and os.path.exists(tc):
        try:
            z = np.load(tc, allow_pickle=False)
            if (list(z["hostnames"]) == hostnames
                    and z["edges"].shape[0] == H and z["edges"].shape[1] == D):
                E, M = z["edges"], z["mask"]
                cat_counts = z["cat_counts"]
                t_start = int(z["t_start"])
                n = kept = out_of_order = truncated = 0
                cur_day = D - 1
                file_cut = None
                novelty_stats = {}
                if "novelty_stats" in z.files:
                    _v = z["novelty_stats"]
                    novelty_stats = dict(
                        mean_new_peer_ratio=float(_v[0]),
                        mean_new_service_flag=float(_v[1]),
                        hosts_peer_memory_saturated=int(_v[2]),
                        edges_scored=int(_v[3]),
                        baseline_days=int(_v[4]) if len(_v) > 4 else nb_days)
                if verbose:
                    print(f"    [cache] tensors loaded from {tc}", flush=True)
            else:
                print(f"    [cache] {tc} does not match this host set; rebuilding")
        except Exception as e:                      # pragma: no cover
            print(f"    [cache] unreadable ({e}); rebuilding")
            E = M = None

    if E is None and not flows_path:
        raise RuntimeError(
            f"no flows.txt(.gz) under {root}, and the tensor cache that would "
            f"have replaced it is missing or does not match this host set "
            f"(looked for lanl_tensors_{cache_key}.npz under "
            f"{tensor_cache!r}). The cache key encodes hosts, days and the "
            f"novelty flag, so --max-hosts / --lanl-days / --no-novelty must "
            f"match the run that wrote it.")
    if E is None:
        (E, M, cat_counts, t_start, n, kept, out_of_order, truncated,
         cur_day, file_cut, novelty_stats) = _pass_two(
            flows_path, ids, keep, fanin, hi, vhi, H, D, progress_every,
            verbose, novelty=novelty, baseline_days=nb_days)
        if tc:
            try:
                np.savez_compressed(
                    tc, edges=E, mask=M, cat_counts=cat_counts,
                    t_start=np.int64(t_start), hostnames=np.array(hostnames),
                    novelty_stats=np.array([
                        novelty_stats.get("mean_new_peer_ratio", float("nan")),
                        novelty_stats.get("mean_new_service_flag", float("nan")),
                        novelty_stats.get("hosts_peer_memory_saturated", 0),
                        novelty_stats.get("edges_scored", 0),
                        novelty_stats.get("baseline_days", 0)], dtype=np.float64))
                if verbose:
                    print(f"    [cache] wrote {tc}", flush=True)
            except Exception as e:                  # pragma: no cover
                print(f"    [cache] write failed ({e})")

    # ---- red-team labels -------------------------------------------------
    A_day = np.zeros((H, D), dtype=bool)
    A_win = np.zeros((H, D, WINDOWS_PER_DAY), dtype=bool)
    rt_hit = rt_miss = rt_out_of_range = 0
    src_kept, dst_kept = set(), set()
    for (t, s, dcomp) in rt:
        off = t - (t_start if t_start is not None else 0)
        d = off // SECONDS_PER_DAY
        if d < 0 or d >= D:
            rt_out_of_range += 1
            continue
        w = (off % SECONDS_PER_DAY) // WINDOW_SECONDS
        marked = False
        sides = {"both": ((s, src_kept), (dcomp, dst_kept)),
                 "src": ((s, src_kept),),
                 "dst": ((dcomp, dst_kept),)}[label_policy]
        for comp, bucket in sides:
            gid = ids.get(comp)
            h = keep.get(gid) if gid is not None else None
            if h is not None:                # BOTH endpoints -- stated choice
                A_day[h, d] = True
                A_win[h, d, w] = True
                bucket.add(comp)
                marked = True
        rt_hit += marked
        rt_miss += (not marked)

    live = int((M.sum(-1) > 0).sum())
    if verbose:
        print(f"\n    parsed {n:,} rows, kept {kept:,} client-flows over "
              f"{min(cur_day + 1, D)} day(s) in {time.time() - t0:.0f}s"
              + ("  [from cache]" if n == 0 else ""))
        if out_of_order:
            print(f"    !! {out_of_order:,} out-of-order rows dropped "
                  f"(file is expected to be time-sorted)")
        if truncated:
            print(f"    {truncated:,} timestamps past the {TS_CAP}/bucket cap "
                  f"(head kept; periodicity preserved, coverage partial)")
        print(f"    live windows {live:,}   density {M.mean():.4f}")
        n_src = len({s for _t, s, _d in rt}); n_dst = len({x for _t, _s, x in rt})
        print(f"    red-team events {len(rt):,}  ->  {rt_hit:,} touched a kept "
              f"host, {rt_miss:,} did not"
              + (f", {rt_out_of_range:,} outside day range" if rt_out_of_range else ""))
        print(f"      label policy: {label_policy.upper()}")
        if label_policy in ("both", "src"):
            print(f"      red-team SOURCE computers      {len(src_kept):,}/{n_src:,} modelled")
        if label_policy in ("both", "dst"):
            print(f"      red-team DESTINATION computers {len(dst_kept):,}/{n_dst:,} modelled")
        if label_policy in ("both", "dst") and n_dst and len(dst_kept) / n_dst < 0.5:
            print("      note: most red-team destinations are servers with no")
            print("      client-side traffic, so they are not modelled hosts.")
            print("      Attack recall here is recall on the compromised SOURCE,")
            print("      which is the host NetSentinel is meant to catch anyway.")
        print(f"    attack host-days {int(A_day.sum()):,} / {H*D:,}  "
              f"({A_day.sum()/max(H*D,1)*100:.3f}%)")
        if novelty:
            ns = novelty_stats or {}
            print("    feature slots 2/3 carry NOVELTY on this dataset "
                  "(bytes_down and egress_asymmetry are uncomputable):")
            print(f"      profile learned over days 0..{nb_days - 1}, then FROZEN")
            print(f"      new_peer_ratio    mean {ns.get('mean_new_peer_ratio', float('nan')):.4f}")
            print(f"      new_service_flag  mean {ns.get('mean_new_service_flag', float('nan')):.4f}")
            sat = ns.get("hosts_peer_memory_saturated", 0)
            if sat:
                print(f"      !! {sat} host(s) hit the {PEER_MEMORY_CAP}-peer memory cap; "
                      f"their novelty is pinned to 0 and understated.")
            if ns.get("mean_new_peer_ratio", 0) > 0.9:
                print("      >> Almost every peer looks new. The prefix has no")
                print("         history to work with -- too few days, or hosts")
                print("         too sparse. Novelty carries no signal here.")
        else:
            print("    !! egress_asymmetry and log_bytes_down are ZERO on this "
                  "dataset: cyber1 logs one byte count, not a directional pair.")
        if file_cut or prof.get("truncation"):
            last = min(cur_day, D - 1)
            print(f"    !! flows.txt.gz IS TRUNCATED. Usable data ends inside "
                  f"day {last}; day {last} is partial and days after it are "
                  f"EMPTY.")
            print(f"       Re-run with --lanl-days {max(last, 1)} to drop the "
                  f"partial day, or re-download the file.")

    return dict(
        edges=E, mask=M,
        is_attack_day=A_day, is_attack_window=A_win,
        stealth=np.zeros(H, dtype=np.float32),
        roles=np.array(["unknown"] * H),          # unused by every model
        host_ids=np.arange(H), hostnames=np.array(hostnames),
        categories=list(LANL_CATEGORIES),
        category_counts={c: int(cat_counts[i])
                         for i, c in enumerate(LANL_CATEGORIES)},
        feature_available=[True] * N_EDGE_FEATURES if novelty else
                          [i not in UNAVAILABLE_FEATURES
                           for i in range(N_EDGE_FEATURES)],
        feature_names=feature_names(novelty),
        novelty=bool(novelty), novelty_stats=novelty_stats,
        fanin_p90=hi, fanin_p99=vhi,
        redteam_events=len(rt), redteam_matched=rt_hit,
        redteam_sources_modelled=len(src_kept),
        redteam_dests_modelled=len(dst_kept),
        redteam_hosts_forced=forced,
        file_truncated=bool(file_cut or prof.get("truncation")),
        truncation_detail=file_cut or prof.get("truncation"),
        last_usable_day=int(min(cur_day, D - 1)),
        label_policy={
            "both": "both endpoints of each red-team auth event marked",
            "src":  "only the SOURCE (beachhead) of each red-team auth event",
            "dst":  "only the DESTINATION (victim) of each red-team auth event",
        }[label_policy],
        source=flows_path,
    )


def feature_names(novelty: bool = True) -> list[str]:
    """The schema as it actually is on this dataset -- never assume the
    generator's names still describe the columns."""
    from .categories import EDGE_FEATURES
    names = list(EDGE_FEATURES)
    if novelty:
        for i, nm in NOVELTY_FEATURES.items():
            names[i] = nm
    else:
        for i in UNAVAILABLE_FEATURES:
            names[i] = names[i] + " (ZERO/unavailable)"
    return names


def summarise(d) -> str:
    E, M = d["edges"], d["mask"]
    per = M.sum(axis=(0, 1, 2))
    tot = max(per.sum(), 1)
    lines = [f"hosts={E.shape[0]}  days={E.shape[1]}  "
             f"live windows={int((M.sum(-1) > 0).sum()):,}  "
             f"density={M.mean():.4f}"]
    for c, nn in sorted(zip(d.get("categories", LANL_CATEGORIES), per),
                        key=lambda x: -x[1]):
        if nn:
            lines.append(f"    {c:14s} {int(nn):>9,}  {nn/tot*100:5.1f}%")
    return "\n".join(lines)



def _pass_two(flows_path, ids, keep, fanin, hi, vhi, H, D,
              progress_every, verbose, novelty=True, baseline_days=None):
    """Stream the flow file into the tensors, flushing one day at a time."""
    E = np.zeros((H, D, WINDOWS_PER_DAY, N_CATEGORIES, N_EDGE_FEATURES),
                 dtype=np.float32)
    M = np.zeros((H, D, WINDOWS_PER_DAY, N_CATEGORIES), dtype=np.float32)
    rng = np.random.default_rng(0)
    cat_counts = np.zeros(N_CATEGORIES, dtype=np.int64)

    # bucket: (host_row, window, cat) -> [n, bytes, dur_sum, ts(array), peers(set)]
    def new_bucket():
        # 'q' = signed 64-bit. NOT 'l': that is 4 bytes on Windows and 8 on
        # Linux, so the buffer would be reinterpreted wrongly across platforms.
        return [0, 0.0, 0.0, array("q"), set()]

    # Causal prefix memory: what each host has been seen to do BEFORE the
    # window currently being written. Never reset, never rebuilt from the
    # future, so novelty means the same thing in commissioning and in test.
    seen_peers: dict[int, set] = defaultdict(set)
    seen_cats: dict[int, set] = defaultdict(set)
    saturated: set = set()
    if baseline_days is None:
        baseline_days = max(1, D // 2)
    nov_sum = [0.0, 0.0]
    nov_n = 0

    def flush(day_idx, buckets):
        nonlocal nov_n
        if day_idx < 0 or day_idx >= D:
            return
        # Windows MUST be applied in time order or "seen before" is a lie.
        # dict iteration order is insertion order, which is arrival order --
        # close, but a late flow can create window w-1 after window w. Sort.
        for key in sorted(buckets.keys()):
            h, w, c = key
            n, byt, dur, ts, peers = buckets[key]
            a = np.asarray(ts, dtype=np.float64) if len(ts) else np.array([0.0])
            a.sort()
            iats = np.diff(a) if a.size > 1 else np.array([0.0])
            row = _edge_row(rng, n, byt, 0.0, iats,
                            distinct_ratio=len(peers) / max(n, 1),
                            dur_mean=dur / max(n, 1))
            if novelty:
                learning = day_idx < baseline_days
                known = seen_peers[h]
                if h in saturated:
                    # Memory is full for this host; claiming novelty now would
                    # be an artefact of the cap, so claim none and say so.
                    new_ratio = 0.0
                else:
                    new_ratio = (len(peers - known) / len(peers)) if peers else 0.0
                first_use = 0.0 if c in seen_cats[h] else 1.0
                row[2] = np.float32(new_ratio)
                row[3] = np.float32(first_use)
                nov_sum[0] += new_ratio; nov_sum[1] += first_use; nov_n += 1
                # Update the profile AFTER scoring, and only while still
                # commissioning. Past that the profile is frozen and novelty
                # keeps reporting for as long as the host stays off-profile.
                if learning:
                    if len(known) < PEER_MEMORY_CAP:
                        known |= peers
                        if len(known) >= PEER_MEMORY_CAP:
                            saturated.add(h)
                    seen_cats[h].add(c)
            else:
                for fi in UNAVAILABLE_FEATURES:
                    row[fi] = 0.0        # honest zero, not a fabricated split
            E[h, day_idx, w, c] = row
            M[h, day_idx, w, c] = 1.0
            cat_counts[c] += 1

    t_start = None
    cur_day = -1
    buckets: dict[tuple, list] = defaultdict(new_bucket)
    n = kept = out_of_order = 0
    truncated = 0
    t0 = time.time()
    file_cut = None
    with _open(flows_path) as f:
      try:
        for line in _safe_lines(f):
            n += 1
            if progress_every and n % progress_every == 0:
                rate = n / max(time.time() - t0, 1e-9)
                print(f"    [load] {n:,} rows  day {cur_day}  kept {kept:,}  "
                      f"({rate/1e6:.2f}M rows/s)", flush=True)
            p = line.rstrip("\n").split(",")
            if len(p) < 9:
                continue
            try:
                t = int(p[0]); dur = float(p[1]); byt = float(p[8])
            except ValueError:
                continue
            if t_start is None:
                t_start = t
            off = t - t_start
            d = off // SECONDS_PER_DAY
            if d < cur_day:
                out_of_order += 1
                continue
            if d != cur_day:
                flush(cur_day, buckets)
                buckets = defaultdict(new_bucket)
                cur_day = d
                if d >= D:
                    break

            src, sp, dst, dp = p[2], p[3], p[4], p[5]
            si, di = ids.get(src), ids.get(dst)
            if si is None or di is None:
                continue                 # unseen during a truncated profile
            ps, pd = _port_num(sp), _port_num(dp)
            if ps is not None and pd is None:
                cli, peer = di, si
            else:
                cli, peer = si, di
            h = keep.get(cli)
            if h is None:
                continue
            cat = LCAT[classify(sp, dp, fanin.get(peer, 0), hi, vhi)]
            w = (off % SECONDS_PER_DAY) // WINDOW_SECONDS
            b = buckets[(h, w, cat)]
            b[0] += 1
            b[1] += byt
            b[2] += dur
            if len(b[3]) < TS_CAP:
                b[3].append(t)
            else:
                truncated += 1
            if len(b[4]) < 4096:
                b[4].add(peer)
            kept += 1
      except _Truncated as e:
        # A 12 GB download that stopped short. Every complete row before the
        # cut is valid, so keep them, flush the partial day, and hand the
        # caller enough to say loudly which day the data actually ends on.
        file_cut = e.reason
        print(f"\n    !! gzip stream ends early at row {n:,} on day {cur_day} "
              f"({file_cut})", flush=True)
        print("       Every complete row before the cut is kept. The last day "
              "is PARTIAL --", flush=True)
        print("       lower --lanl-days by one, or re-download flows.txt.gz, "
              "before quoting", flush=True)
        print("       anything that depends on a full final day.", flush=True)
    flush(cur_day, buckets)
    stats = dict(
        mean_new_peer_ratio=(nov_sum[0] / nov_n) if nov_n else float("nan"),
        mean_new_service_flag=(nov_sum[1] / nov_n) if nov_n else float("nan"),
        hosts_peer_memory_saturated=len(saturated),
        edges_scored=nov_n, baseline_days=int(baseline_days),
    )
    return (E, M, cat_counts, t_start, n, kept,
            out_of_order, truncated, cur_day, file_cut, stats)
