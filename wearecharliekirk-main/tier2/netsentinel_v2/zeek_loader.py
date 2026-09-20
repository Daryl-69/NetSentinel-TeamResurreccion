"""Zeek logs -> the same (host, day, window, category, feature) tensor the
generator produces. This is the seam that lets real traffic replace `synth`
without touching models.py, baseline.py or train.py.

Input: a directory of Zeek logs (TSV or JSON). Uses conn.log for volume and
timing, ssl.log for SNI and dns.log for query names so the Service Category
Resolver has a hostname to work with. Where both are missing (ECH, DoH, raw IP)
the flow lands in `Unknown_External` — which is deliberate: an unknown-category
transition is itself informative, and pretending otherwise hides how much
visibility you have actually lost.

Works on: Stratosphere Normal Captures (Bro/Zeek format), CTU-13, IoT-23, and
your own `zeek -i <iface>` capture. See DATASETS.md.
"""

from __future__ import annotations

import gzip, io, json, os, re
from collections import defaultdict

import numpy as np

from .categories import CAT_INDEX, N_CATEGORIES, N_EDGE_FEATURES
from .synth import _edge_row, WINDOWS_PER_DAY

# --- Service Category Resolver (deterministic, taxonomy-driven) ------------
# Extend from the LOTS Project taxonomy; keep it a lookup, never a model.
RULES = [
    ("Recon_API",       r"(ip-api\.com|ipify\.org|ifconfig\.me|icanhazip|ipinfo\.io|myexternalip)"),
    ("Code_Repo_Paste", r"(github|githubusercontent|gitlab|bitbucket|pastebin|paste\.ee|gist\.)"),
    ("Messaging_API",   r"(telegram|discord|slack\.com|teams\.microsoft|graph\.microsoft"
                        r"|mattermost|intercom\.io|zoom\.us|webex)"),
    ("Cloud_Storage",   r"(drive\.google|docs\.google|dropbox|onedrive|1drv\.ms"
                        r"|s3[.-].*amazonaws|box\.com|mega\.nz|storage\.googleapis"
                        r"|substrate\.office|officeclient\.microsoft|sharepoint"
                        r"|blob\.core\.windows\.net)"),
    ("CI_CD",           r"(circleci|travis-ci|jenkins|actions\.github|codecov|docker\.io"
                        r"|ghcr\.io|pypi\.org|registry\.npmjs)"),
    # Automated background traffic: telemetry, settings pulls and updaters are
    # machine-driven and periodic, which is what this slot means. Leaving them
    # in the Browse catch-all put 63% of real flows in one undifferentiated
    # bucket (measured on our own capture) and flattened the signal.
    ("Sync",            r"(sync\.|clientsync|dropboxusercontent|apple-cloudkit|icloud"
                        r"|events\.data\.microsoft|settings-win\.data\.microsoft"
                        r"|-updater\.|updatecheck|oneclient\.sfx\.ms|edgedl|gvt1\.com)"),
]
_COMPILED = [(c, re.compile(p, re.I)) for c, p in RULES]

# Internal-address test. IPv4 uses RFC1918; IPv6 needs its own rules and this
# is NOT optional -- a laptop's GLOBAL IPv6 address matches no private range,
# so an IPv4-only test silently treats every IPv6 peer as external. On our own
# capture that is 52% of packets (measured, pcap_to_tensor.py).
#
# Addresses arrive in two spellings: colon form ("fe80::1") from Zeek logs and
# bare 32-hex-char form from the raw-packet path. Both are handled.
_PRIVATE_V4 = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)")
_PRIVATE_V6 = re.compile(r"^(fe[89ab]|f[cd])", re.I)


class _PrivateMatcher:
    """Callable as `_PRIVATE.match(ip)` so every existing call site is
    unchanged -- but correct for IPv6."""

    @staticmethod
    def match(ip):
        if not ip:
            return None
        if "." in ip and ":" not in ip:
            return _PRIVATE_V4.match(ip)
        flat = ip.replace(":", "").lower()
        if ip == "::1" or (flat.strip("0") == "1" and len(flat) <= 32):
            return True
        return _PRIVATE_V6.match(flat) or None


_PRIVATE = _PrivateMatcher


def resolve_category(hostname: str | None, dest_ip: str | None) -> str:
    if hostname:
        for cat, rx in _COMPILED:
            if rx.search(hostname):
                return cat
        return "Browse"
    if dest_ip and _PRIVATE.match(dest_ip):
        return "Internal"
    return "Unknown_External"      # ECH / DoH / raw-IP: visibility genuinely lost


# --- Zeek log reading (TSV with #fields header, or JSON lines) -------------
def _open(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") \
        else open(path, "rt", errors="replace")


def read_zeek(path: str):
    """Yield dicts, one per record. Handles Zeek TSV and JSON-lines."""
    if not os.path.exists(path):
        return
    with _open(path) as f:
        fields, sep = None, "\t"
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#separator"):
                    s = line.split(" ", 1)[1].strip()
                    sep = s.encode().decode("unicode_escape") if s.startswith("\\") else s
                continue
            if fields is None:                       # JSON-lines
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass
                continue
            parts = line.split(sep)
            if len(parts) == len(fields):
                yield dict(zip(fields, parts))


def find_log(zeek_dir: str, base: str) -> str | None:
    """Resolve 'conn' -> conn.log / conn.log.gz / conn.log.labeled / ...

    Zeek ships logs plain, gzipped, or label-suffixed depending on the
    publisher. Looking for the bare name only means a .gz ssl.log is silently
    skipped, every destination falls through to Unknown_External, and the run
    reports "the resolver is blind" -- a false conclusion from a missing file.
    """
    for name in (f"{base}.log", f"{base}.log.gz", f"{base}.log.labeled",
                 f"{base}.log.labeled.gz", f"{base}.gz", base):
        p = os.path.join(zeek_dir, name)
        if os.path.exists(p):
            return p
    return None


def _num(v, default=0.0):
    try:
        if v in ("-", "(empty)", "", None):
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


def load_dir(zeek_dir: str, window_seconds: int = 3600,
             min_windows_per_host: int = 48, max_hosts: int | None = None):
    """Build the tensors from one directory of Zeek logs.

    Returns the same dict shape as synth.generate():
      edges (H,D,W,C,F)  mask (H,D,W,C)  host_ids, and `hostnames`.
    `is_attack_day` is all-False — real benign capture carries no attack labels,
    which is the point: the Inspector is an anomaly model and never needs them.
    """
    conn = find_log(zeek_dir, "conn")
    ssl_p = find_log(zeek_dir, "ssl")
    dns_p = find_log(zeek_dir, "dns")
    if conn is None:
        raise RuntimeError(f"no conn.log (or .gz/.labeled) under {zeek_dir}")
    print(f"    conn: {os.path.basename(conn)}"
          f"   ssl: {os.path.basename(ssl_p) if ssl_p else 'MISSING'}"
          f"   dns: {os.path.basename(dns_p) if dns_p else 'MISSING'}", flush=True)
    if not ssl_p and not dns_p:
        print("    !! no ssl.log and no dns.log -- there are NO hostnames to resolve,"
              " so every external destination will be Unknown_External.", flush=True)

    # uid -> hostname, from ssl (SNI) then dns (query)
    uid_host: dict[str, str] = {}
    for rec in read_zeek(ssl_p) if ssl_p else ():
        sn = rec.get("server_name") or rec.get("server_name.")
        if sn and sn != "-":
            uid_host[rec.get("uid", "")] = sn
    ip_host: dict[str, str] = {}
    for rec in read_zeek(dns_p) if dns_p else ():
        q, ans = rec.get("query"), rec.get("answers")
        if q and q != "-" and ans and ans != "-":
            for a in str(ans).split(","):
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", a.strip()):
                    ip_host[a.strip()] = q

    # (host, abs_window, category) -> list of flow tuples
    print(f"    SNI names from ssl.log: {len(uid_host):,}"
          f"   DNS A-records: {len(ip_host):,}", flush=True)

    buckets: dict[tuple, list] = defaultdict(list)
    t_min = None
    n_rec = 0
    for rec in read_zeek(conn):
        n_rec += 1
        if n_rec % 500_000 == 0:
            print(f"    ... {n_rec:,} conn records", flush=True)
        ts = _num(rec.get("ts"))
        if ts <= 0:
            continue
        src, dst = rec.get("id.orig_h"), rec.get("id.resp_h")
        if not src or not dst:
            continue
        t_min = ts if t_min is None else min(t_min, ts)
        name = uid_host.get(rec.get("uid", "")) or ip_host.get(dst)
        cat = resolve_category(name, dst)
        buckets[(src, int(ts // window_seconds), cat)].append((
            ts,
            _num(rec.get("orig_bytes")),
            _num(rec.get("resp_bytes")),
            _num(rec.get("duration")),
            dst,
        ))
    if not buckets:
        raise RuntimeError(f"no conn.log records found under {zeek_dir}")
    print(f"    parsed {n_rec:,} conn records", flush=True)

    hosts = sorted({k[0] for k in buckets})
    counts = defaultdict(set)
    for (h, w, _c) in buckets:
        counts[h].add(w)
    hosts = [h for h in hosts if len(counts[h]) >= min_windows_per_host]
    if not hosts:                        # short captures: keep everything
        hosts = sorted({k[0] for k in buckets})
    if max_hosts:
        hosts = sorted(hosts, key=lambda h: -len(counts[h]))[:max_hosts]
    hidx = {h: i for i, h in enumerate(hosts)}

    w0 = min(k[1] for k in buckets)
    w1 = max(k[1] for k in buckets)
    n_windows = w1 - w0 + 1
    n_days = max(1, int(np.ceil(n_windows / WINDOWS_PER_DAY)))

    H, D, W, C, F = len(hosts), n_days, WINDOWS_PER_DAY, N_CATEGORIES, N_EDGE_FEATURES
    E = np.zeros((H, D, W, C, F), dtype=np.float32)
    M = np.zeros((H, D, W, C), dtype=np.float32)
    rng = np.random.default_rng(0)

    for (host, aw, cat), flows in buckets.items():
        if host not in hidx:
            continue
        off = aw - w0
        d, w = divmod(off, WINDOWS_PER_DAY)
        if d >= D:
            continue
        flows.sort()
        ts = np.array([f[0] for f in flows])
        iats = np.diff(ts) if ts.size > 1 else np.array([0.0])
        up = float(sum(f[1] for f in flows))
        down = float(sum(f[2] for f in flows))
        dur = float(np.mean([f[3] for f in flows]))
        distinct = len({f[4] for f in flows}) / max(len(flows), 1)
        E[hidx[host], d, w, CAT_INDEX[cat]] = _edge_row(
            rng, len(flows), up, down, iats, distinct, dur)
        M[hidx[host], d, w, CAT_INDEX[cat]] = 1.0

    return dict(edges=E, mask=M,
                is_attack_day=np.zeros((H, D), dtype=bool),
                stealth=np.zeros(H, dtype=np.float32),
                roles=np.array(["unknown"] * H),
                host_ids=np.arange(H), hostnames=np.array(hosts),
                source=zeek_dir)


def summarise(d):
    E, M = d["edges"], d["mask"]
    from .categories import CATEGORIES
    per_cat = M.sum(axis=(0, 1, 2))
    lines = [f"hosts={E.shape[0]}  days={E.shape[1]}  live windows="
             f"{int((M.sum(-1) > 0).sum())}  density={M.mean():.3f}"]
    for c, n in sorted(zip(CATEGORIES, per_cat), key=lambda x: -x[1]):
        if n:
            lines.append(f"    {c:18s} {int(n):>8,}")
    return "\n".join(lines)
